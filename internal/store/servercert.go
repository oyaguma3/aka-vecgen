package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
)

// サーバー証明書の出所。
const (
	CertSourceSelfSigned = "self-signed"
	CertSourceUploaded   = "uploaded"
)

// CertSlot はサーバー証明書の保存先。
type CertSlot string

const (
	// CertSlotAV は認証ベクターAPI 用のサーバー証明書。
	CertSlotAV CertSlot = "cfg:av_tls"
	// CertSlotAdmin は管理API 用のサーバー証明書。
	CertSlotAdmin CertSlot = "cfg:admin_tls"
)

// ServerCertificate はサーバー証明書と秘密鍵。
// 秘密鍵は Valkey では KEK で暗号化して持ち（key_enc・key_kek。確認事項 D2）、ここでは復号した PEM を入れる。
type ServerCertificate struct {
	CertPEM   []byte
	KeyPEM    []byte
	Source    string
	UpdatedAt time.Time
}

// KEYS: 保存先
// ARGV: cert_pem, key_enc（暗号化した秘密鍵）, key_kek（KEK の識別子）, source, updated_at
var initServerCertificateScript = valkey.NewLuaScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
redis.call('HSET', KEYS[1], 'cert_pem', ARGV[1], 'key_enc', ARGV[2], 'key_kek', ARGV[3], 'source', ARGV[4], 'updated_at', ARGV[5])
return 1
`)

// KEYS: 保存先
// ARGV: cert_pem, key_enc, key_kek, source, updated_at
var setServerCertificateScript = valkey.NewLuaScript(`
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[1], 'cert_pem', ARGV[1], 'key_enc', ARGV[2], 'key_kek', ARGV[3], 'source', ARGV[4], 'updated_at', ARGV[5])
return 1
`)

// ErrCertKeyInvalid はサーバー証明書の秘密鍵を読めないこと（平文のまま、別の KEK、壊れている）を表す。
var ErrCertKeyInvalid = errors.New("server certificate key is not readable")

// sealCertKey はサーバー証明書の秘密鍵を暗号化する。
func (s *Store) sealCertKey(slot CertSlot, keyPEM []byte) (string, error) {
	if s.kek == nil {
		return "", ErrNoKEK
	}
	b, err := s.kek.Seal(keyPEM, certAAD(slot))
	return string(b), err
}

// ServerCertificate は保存されているサーバー証明書を返す。なければ ErrNotFound を返す。
func (s *Store) ServerCertificate(ctx context.Context, slot CertSlot) (ServerCertificate, error) {
	f, err := s.c.Do(ctx, s.c.B().Hgetall().Key(string(slot)).Build()).AsStrMap()
	if err != nil {
		return ServerCertificate{}, fmt.Errorf("get server certificate: %w", err)
	}
	if len(f) == 0 {
		return ServerCertificate{}, ErrNotFound
	}
	if s.kek == nil {
		return ServerCertificate{}, ErrNoKEK
	}
	switch {
	case f["key_enc"] == "":
		return ServerCertificate{}, fmt.Errorf("%w: %s has no encrypted key (written before the KEK; delete the key %s to create a new certificate)",
			ErrCertKeyInvalid, certSlotName(slot), string(slot))
	case f["key_kek"] != s.kek.ID():
		return ServerCertificate{}, fmt.Errorf("%w: %s is encrypted with another KEK (%s)", ErrCertKeyInvalid, certSlotName(slot), f["key_kek"])
	}
	keyPEM, err := s.kek.Open([]byte(f["key_enc"]), certAAD(slot))
	if err != nil {
		return ServerCertificate{}, fmt.Errorf("%w: %s: %v", ErrCertKeyInvalid, certSlotName(slot), err)
	}
	return ServerCertificate{
		CertPEM:   []byte(f["cert_pem"]),
		KeyPEM:    keyPEM,
		Source:    f["source"],
		UpdatedAt: parseTime(f["updated_at"]),
	}, nil
}

// InitServerCertificate は、サーバー証明書がまだ保存されていない場合に限り保存する。
// 既にあれば何もせず false を返す。
func (s *Store) InitServerCertificate(ctx context.Context, slot CertSlot, certPEM, keyPEM []byte, source string) (bool, error) {
	enc, err := s.sealCertKey(slot, keyPEM)
	if err != nil {
		return false, fmt.Errorf("init server certificate: %w", err)
	}
	args := []string{string(certPEM), enc, s.kek.ID(), source, now()}
	n, err := initServerCertificateScript.Exec(ctx, s.c, []string{string(slot)}, args).AsInt64()
	if err != nil {
		return false, fmt.Errorf("init server certificate: %w", err)
	}
	return n == 1, nil
}

// SetServerCertificate はサーバー証明書を置き換える。
func (s *Store) SetServerCertificate(ctx context.Context, slot CertSlot, certPEM, keyPEM []byte, source string) error {
	enc, err := s.sealCertKey(slot, keyPEM)
	if err != nil {
		return fmt.Errorf("set server certificate: %w", err)
	}
	// 古い平文の key_pem が残らないよう、行ごと書き直す
	args := []string{string(certPEM), enc, s.kek.ID(), source, now()}
	if err := setServerCertificateScript.Exec(ctx, s.c, []string{string(slot)}, args).Error(); err != nil {
		return fmt.Errorf("set server certificate: %w", err)
	}
	return nil
}
