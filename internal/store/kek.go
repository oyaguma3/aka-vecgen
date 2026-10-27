package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/oyaguma3/aka-vecgen/internal/kek"
)

// KEK の識別と確認のキー（設計概要 §8）
const (
	keyKEK         = "cfg:kek"          // KEK の識別子
	keyKEKCheck    = "cfg:kek_check"    // 決まった値を KEK で暗号化したもの（起動の確認に使う）
	keyKEKRotation = "cfg:kek_rotation" // rotate-kek の間だけ立てる（値は 古い識別子:新しい識別子）
	keyServeAlive  = "cfg:serve:alive"  // serve が動いている印（TTL つき。値は起動の ID）

	kekCheckPlain = "aka-vecgen kek check"
	kekCheckAAD   = "aka-vecgen/cfg/kek_check"

	// ServeAliveInterval は serve が動いている印を書き直す間隔。
	ServeAliveInterval = 10 * time.Second
	// serveAliveTTL は動いている印の期限。serve が止まってから、この時間がたつと rotate-kek ができる。
	serveAliveTTL = 30 * time.Second
	// rotateBatch は rotate-kek で一度に読む加入者の数。
	rotateBatch = 500
)

var (
	// ErrNoKEK は KEK を設定していない Store で鍵を扱おうとしたことを表す。
	ErrNoKEK = errors.New("kek is not configured")
	// ErrKEKMismatch は KEK が Valkey の識別子・確認の値と合わないことを表す。
	ErrKEKMismatch = errors.New("kek does not match the one in valkey")
	// ErrKEKMissing は cfg:kek がないのに暗号化したデータがあることを表す（別の KEK で始めてしまうのを防ぐ）。
	ErrKEKMissing = errors.New("cfg:kek is missing although encrypted data exists")
	// ErrKEKRotationInProgress は rotate-kek が途中であることを表す。
	ErrKEKRotationInProgress = errors.New("kek rotation is in progress (run rotate-kek again with the same files to finish it)")
	// ErrServeRunning は serve が動いているので rotate-kek ができないことを表す。
	ErrServeRunning = errors.New("aka-vecgen serve is running (stop it before rotate-kek)")
	// ErrCredInvalid は加入者の暗号化した鍵が読めないこと（平文の行、別の KEK、壊れている）を表す。
	ErrCredInvalid = errors.New("subscriber credentials are not readable")
)

func subAAD(imsi string) string    { return "aka-vecgen/sub/" + imsi }
func certAAD(slot CertSlot) string { return "aka-vecgen/cert/" + certSlotName(slot) }
func certSlotName(s CertSlot) string {
	switch s {
	case CertSlotAV:
		return "av"
	case CertSlotAdmin:
		return "admin"
	}
	return string(s)
}

// KEKID は使っている KEK の識別子を返す（KEK がなければ空文字列）。
func (s *Store) KEKID() string {
	if s.kek == nil {
		return ""
	}
	return s.kek.ID()
}

// 初めての起動の判定と KEK の確認（設計概要 §8.2、確認事項 D4）。
//
// KEYS: cfg:kek, cfg:kek_check, subs, cfg:kek_rotation, cfg:av_tls, cfg:admin_tls
// ARGV: KEK の識別子, 確認の値（初めての起動のときに書く）
var setupKEKScript = valkey.NewLuaScript(`
if redis.call('EXISTS', KEYS[4]) == 1 then
  return {'ROTATING'}
end
local cur = redis.call('GET', KEYS[1])
if cur then
  return {'EXISTS', cur, redis.call('GET', KEYS[2]) or ''}
end
if redis.call('ZCARD', KEYS[3]) > 0 or redis.call('HEXISTS', KEYS[5], 'key_enc') == 1 or redis.call('HEXISTS', KEYS[6], 'key_enc') == 1 then
  return {'MISSING_WITH_DATA'}
end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('SET', KEYS[2], ARGV[2])
return {'INIT'}
`)

// SetupKEK は KEK を確かめて Store に設定する。
// cfg:kek がなく、加入者も暗号化したサーバー証明書もなければ、初めての起動として識別子と確認の値を書き、true を返す。
// cfg:kek がないのにデータがあれば ErrKEKMissing、識別子か確認の値が合わなければ ErrKEKMismatch、
// rotate-kek の途中なら ErrKEKRotationInProgress を返す。
func (s *Store) SetupKEK(ctx context.Context, k *kek.KEK) (bool, error) {
	check, err := k.Seal([]byte(kekCheckPlain), kekCheckAAD)
	if err != nil {
		return false, err
	}
	keys := []string{keyKEK, keyKEKCheck, keySubs, keyKEKRotation, string(CertSlotAV), string(CertSlotAdmin)}
	out, err := setupKEKScript.Exec(ctx, s.c, keys, []string{k.ID(), string(check)}).AsStrSlice()
	if err != nil {
		return false, fmt.Errorf("setup kek: %w", err)
	}
	switch out[0] {
	case "INIT":
		s.kek = k
		return true, nil
	case "ROTATING":
		return false, ErrKEKRotationInProgress
	case "MISSING_WITH_DATA":
		return false, ErrKEKMissing
	case "EXISTS":
		if err := verifyKEK(k, out[1], out[2]); err != nil {
			return false, err
		}
		s.kek = k
		return false, nil
	}
	return false, fmt.Errorf("setup kek: unexpected reply %q", out[0])
}

// verifyKEK は KEK が識別子と確認の値に合うかを確かめる。
func verifyKEK(k *kek.KEK, id, check string) error {
	if id != k.ID() {
		return fmt.Errorf("%w: valkey has %s, the file is %s", ErrKEKMismatch, id, k.ID())
	}
	if p, err := k.Open([]byte(check), kekCheckAAD); err != nil || string(p) != kekCheckPlain {
		return fmt.Errorf("%w: cfg:kek_check cannot be decrypted", ErrKEKMismatch)
	}
	return nil
}

// sealCred は Ki ‖ OPc を暗号化する。
func (s *Store) sealCred(imsi string, ki, opc []byte) ([]byte, error) {
	if s.kek == nil {
		return nil, ErrNoKEK
	}
	plain := make([]byte, 0, 32)
	plain = append(append(plain, ki...), opc...)
	defer clear(plain)
	return s.kek.Seal(plain, subAAD(imsi))
}

// openCred は暗号化した Ki ‖ OPc を復号する。読めなければ ErrCredInvalid を返す。
func (s *Store) openCred(imsi, cred, credKEK string) (ki, opc []byte, err error) {
	if s.kek == nil {
		return nil, nil, ErrNoKEK
	}
	switch {
	case cred == "":
		return nil, nil, fmt.Errorf("%w: no encrypted credentials (a row written before the KEK)", ErrCredInvalid)
	case credKEK != s.kek.ID():
		return nil, nil, fmt.Errorf("%w: encrypted with another KEK (%s)", ErrCredInvalid, credKEK)
	}
	p, err := s.kek.Open([]byte(cred), subAAD(imsi))
	if err != nil || len(p) != 32 {
		return nil, nil, fmt.Errorf("%w: cannot decrypt", ErrCredInvalid)
	}
	ki, opc = make([]byte, 16), make([]byte, 16)
	copy(ki, p[:16])
	copy(opc, p[16:])
	clear(p)
	return ki, opc, nil
}

// SubscriberKeys は加入者の Ki と OPc を復号して返す（鍵の読み出しの口だけが使う。設計概要 §8.4）。
func (s *Store) SubscriberKeys(ctx context.Context, imsi string) (ki, opc []byte, err error) {
	f, err := s.c.Do(ctx, s.c.B().Hmget().Key(subKey(imsi)).Field("cred", "cred_kek", "state").Build()).ToArray()
	if err != nil {
		return nil, nil, fmt.Errorf("get subscriber keys: %w", err)
	}
	cred, _ := f[0].ToString()
	credKEK, _ := f[1].ToString()
	if state, _ := f[2].ToString(); state == "" {
		return nil, nil, ErrNotFound
	}
	return s.openCred(imsi, cred, credKEK)
}

// MarkServing は serve が動いている印を書く（ServeAliveInterval ごとに呼ぶ）。
func (s *Store) MarkServing(ctx context.Context, bootID string) error {
	cmd := s.c.B().Set().Key(keyServeAlive).Value(bootID).Ex(serveAliveTTL).Build()
	if err := s.c.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("mark serving: %w", err)
	}
	return nil
}

var clearServingScript = valkey.NewLuaScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`)

// ClearServing は、自分が書いた動いている印を消す（止まるときに呼ぶ）。
func (s *Store) ClearServing(ctx context.Context, bootID string) error {
	return clearServingScript.Exec(ctx, s.c, []string{keyServeAlive}, []string{bootID}).Error()
}

// RotateResult は rotate-kek の結果。
type RotateResult struct {
	Rotated      int // 新しい KEK で暗号化し直した加入者
	AlreadyNew   int // 既に新しい KEK だった加入者（やり直しのとき）
	Invalid      int // 読めなかった加入者（平文の行・別の KEK・壊れている）。入れ替えの後も使えない
	Certificates int // 暗号化し直したサーバー証明書の秘密鍵
	Finished     bool
}

// 1 行の暗号文を、KEK の識別子が古いままのときだけ置き換える（途中で止まってもやり直せる）。
//
// KEYS: 行のキー
// ARGV: 暗号文のフィールド, KEK の識別子のフィールド, 古い識別子, 新しい暗号文, 新しい識別子
var rewrapScript = valkey.NewLuaScript(`
if redis.call('HGET', KEYS[1], ARGV[2]) ~= ARGV[3] then
  return 0
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[4], ARGV[2], ARGV[5])
return 1
`)

// KEYS: cfg:kek, cfg:kek_check, cfg:kek_rotation
// ARGV: 新しい識別子, 新しい確認の値
var finishRotationScript = valkey.NewLuaScript(`
redis.call('SET', KEYS[1], ARGV[1])
redis.call('SET', KEYS[2], ARGV[2])
redis.call('DEL', KEYS[3])
return 1
`)

// RotateKEK は、加入者の鍵とサーバー証明書の秘密鍵を新しい KEK で暗号化し直す（設計概要 §8.3）。
// serve が動いていれば ErrServeRunning を返す。行ごとの KEK の識別子を見るので、途中で止まっても同じ KEK でやり直せる。
// 間は cfg:kek_rotation を立て、serve とコマンドが起動しないようにする（確認事項 D3）。
func (s *Store) RotateKEK(ctx context.Context, oldK, newK *kek.KEK, progress func(done, total int)) (RotateResult, error) {
	var res RotateResult
	if oldK.ID() == newK.ID() {
		return res, errors.New("the old and new KEK are the same")
	}
	alive, err := s.c.Do(ctx, s.c.B().Exists().Key(keyServeAlive).Build()).AsInt64()
	if err != nil {
		return res, fmt.Errorf("check serve: %w", err)
	}
	if alive > 0 {
		return res, ErrServeRunning
	}

	f, err := s.c.Do(ctx, s.c.B().Mget().Key(keyKEK, keyKEKCheck, keyKEKRotation).Build()).ToArray()
	if err != nil {
		return res, fmt.Errorf("read kek: %w", err)
	}
	curID, _ := f[0].ToString()
	check, _ := f[1].ToString()
	flag, _ := f[2].ToString()
	want := oldK.ID() + ":" + newK.ID()
	switch {
	case flag != "" && flag != want:
		return res, fmt.Errorf("%w with other KEK files (%s)", ErrKEKRotationInProgress, flag)
	case flag == "" && curID == newK.ID():
		// 既に終わっている
		if err := verifyKEK(newK, curID, check); err != nil {
			return res, err
		}
		res.Finished = true
		return res, nil
	}
	if err := verifyKEK(oldK, curID, check); err != nil {
		return res, err
	}
	if err := s.c.Do(ctx, s.c.B().Set().Key(keyKEKRotation).Value(want).Build()).Error(); err != nil {
		return res, fmt.Errorf("set rotation flag: %w", err)
	}

	total, err := s.c.Do(ctx, s.c.B().Zcard().Key(keySubs).Build()).AsInt64()
	if err != nil {
		return res, fmt.Errorf("count subscribers: %w", err)
	}
	for start := int64(0); start < total; start += rotateBatch {
		imsis, err := s.c.Do(ctx, s.c.B().Zrange().Key(keySubs).Min(strconv.FormatInt(start, 10)).Max(strconv.FormatInt(start+rotateBatch-1, 10)).Build()).AsStrSlice()
		if err != nil {
			return res, fmt.Errorf("list subscribers: %w", err)
		}
		if err := s.rotateSubscribers(ctx, imsis, oldK, newK, &res); err != nil {
			return res, err
		}
		if progress != nil {
			progress(int(start)+len(imsis), int(total))
		}
	}
	for _, slot := range []CertSlot{CertSlotAV, CertSlotAdmin} {
		n, err := s.rotateCertificate(ctx, slot, oldK, newK)
		if err != nil {
			return res, err
		}
		res.Certificates += n
	}

	newCheck, err := newK.Seal([]byte(kekCheckPlain), kekCheckAAD)
	if err != nil {
		return res, err
	}
	if err := finishRotationScript.Exec(ctx, s.c, []string{keyKEK, keyKEKCheck, keyKEKRotation}, []string{newK.ID(), string(newCheck)}).Error(); err != nil {
		return res, fmt.Errorf("finish rotation: %w", err)
	}
	res.Finished = true
	return res, nil
}

func (s *Store) rotateSubscribers(ctx context.Context, imsis []string, oldK, newK *kek.KEK, res *RotateResult) error {
	cmds := make(valkey.Commands, len(imsis))
	for i, imsi := range imsis {
		cmds[i] = s.c.B().Hmget().Key(subKey(imsi)).Field("cred", "cred_kek").Build()
	}
	var writes []valkey.LuaExec
	for i, r := range s.c.DoMulti(ctx, cmds...) {
		f, err := r.ToArray()
		if err != nil {
			return fmt.Errorf("read subscriber: %w", err)
		}
		cred, _ := f[0].ToString()
		credKEK, _ := f[1].ToString()
		switch credKEK {
		case newK.ID():
			res.AlreadyNew++
			continue
		case oldK.ID():
		default:
			res.Invalid++
			continue
		}
		p, err := oldK.Open([]byte(cred), subAAD(imsis[i]))
		if err != nil {
			res.Invalid++
			continue
		}
		sealed, err := newK.Seal(p, subAAD(imsis[i]))
		clear(p)
		if err != nil {
			return err
		}
		writes = append(writes, valkey.LuaExec{
			Keys: []string{subKey(imsis[i])},
			Args: []string{"cred", "cred_kek", oldK.ID(), string(sealed), newK.ID()},
		})
	}
	if len(writes) == 0 {
		return nil
	}
	for _, r := range rewrapScript.ExecMulti(ctx, s.c, writes...) {
		n, err := r.AsInt64()
		if err != nil {
			return fmt.Errorf("rewrite subscriber: %w", err)
		}
		res.Rotated += int(n)
	}
	return nil
}

func (s *Store) rotateCertificate(ctx context.Context, slot CertSlot, oldK, newK *kek.KEK) (int, error) {
	f, err := s.c.Do(ctx, s.c.B().Hmget().Key(string(slot)).Field("key_enc", "key_kek").Build()).ToArray()
	if err != nil {
		return 0, fmt.Errorf("read server certificate: %w", err)
	}
	enc, _ := f[0].ToString()
	encKEK, _ := f[1].ToString()
	if encKEK != oldK.ID() {
		return 0, nil // ない、または既に新しい KEK
	}
	p, err := oldK.Open([]byte(enc), certAAD(slot))
	if err != nil {
		return 0, fmt.Errorf("server certificate %s: %w", certSlotName(slot), err)
	}
	sealed, err := newK.Seal(p, certAAD(slot))
	clear(p)
	if err != nil {
		return 0, err
	}
	n, err := rewrapScript.Exec(ctx, s.c, []string{string(slot)}, []string{"key_enc", "key_kek", oldK.ID(), string(sealed), newK.ID()}).AsInt64()
	if err != nil {
		return 0, fmt.Errorf("rewrite server certificate: %w", err)
	}
	return int(n), nil
}
