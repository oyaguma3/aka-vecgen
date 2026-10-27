package store

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/oyaguma3/aka-vecgen/internal/aka"
)

// State は加入者の状態（設計概要 §7）。
type State string

const (
	StateActive     State = "active"
	StateInactive   State = "inactive"
	StateTerminated State = "terminated"
)

// Valid は既知の状態かを返す。
func (s State) Valid() bool {
	return s == StateActive || s == StateInactive || s == StateTerminated
}

// Subscriber は加入者データ。
type Subscriber struct {
	IMSI             string
	Ki               []byte
	OPc              []byte
	SQN              uint64 // 最後に払い出した SQN
	AMF              uint16
	SQNType          aka.SQNType
	State            State
	StateChangedAt   time.Time
	AllowedClientIDs []int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// KEYS: sub:{imsi}, sub:{imsi}:clients, subs
// ARGV: imsi, 現在日時, ki, opc, sqn, amf, sqn_type, state, 許可クライアントID...
var createSubscriberScript = valkey.NewLuaScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
redis.call('HSET', KEYS[1],
  'ki', ARGV[3], 'opc', ARGV[4], 'sqn', ARGV[5], 'amf', ARGV[6],
  'sqn_type', ARGV[7], 'state', ARGV[8], 'state_changed_at', ARGV[2],
  'created_at', ARGV[2], 'updated_at', ARGV[2])
redis.call('DEL', KEYS[2])
for i = 9, #ARGV do
  redis.call('SADD', KEYS[2], ARGV[i])
end
redis.call('ZADD', KEYS[3], 0, ARGV[1])
return 1
`)

// 物理削除は active でない加入者だけ（設計概要 §7.1）。
//
// KEYS: sub:{imsi}, sub:{imsi}:clients, subs
// ARGV: imsi
var deleteSubscriberScript = valkey.NewLuaScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 'NOT_FOUND'
end
if redis.call('HGET', KEYS[1], 'state') == 'active' then
  return 'ACTIVE'
end
redis.call('DEL', KEYS[1])
redis.call('DEL', KEYS[2])
redis.call('ZREM', KEYS[3], ARGV[1])
return 'OK'
`)

// CreateSubscriber は加入者を登録する。状態は active か inactive でなければならない。
// 同じ IMSI が既にあれば ErrExists、存在しないクライアントID があれば ErrUnknownClient を返す。
func (s *Store) CreateSubscriber(ctx context.Context, sub Subscriber) error {
	if !sub.SQNType.Valid() {
		return fmt.Errorf("unknown SQN type %q", string(sub.SQNType))
	}
	if sub.State != StateActive && sub.State != StateInactive {
		return fmt.Errorf("state must be active or inactive at registration: %q", string(sub.State))
	}
	if err := s.checkClientsExist(ctx, sub.AllowedClientIDs); err != nil {
		return err
	}
	args := []string{
		sub.IMSI, now(),
		hex.EncodeToString(sub.Ki), hex.EncodeToString(sub.OPc),
		strconv.FormatUint(sub.SQN&aka.SQNMask, 10),
		fmt.Sprintf("%04x", sub.AMF),
		string(sub.SQNType), string(sub.State),
	}
	for _, id := range sub.AllowedClientIDs {
		args = append(args, strconv.FormatInt(id, 10))
	}
	keys := []string{subKey(sub.IMSI), subClientsKey(sub.IMSI), keySubs}
	created, err := createSubscriberScript.Exec(ctx, s.c, keys, args).AsInt64()
	if err != nil {
		return fmt.Errorf("create subscriber: %w", err)
	}
	if created == 0 {
		return ErrExists
	}
	return nil
}

func (s *Store) checkClientsExist(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	cmds := make(valkey.Commands, len(ids))
	for i, id := range ids {
		cmds[i] = s.c.B().Exists().Key(clientKey(id)).Build()
	}
	for i, r := range s.c.DoMulti(ctx, cmds...) {
		n, err := r.AsInt64()
		if err != nil {
			return fmt.Errorf("check client: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("%w: %d", ErrUnknownClient, ids[i])
		}
	}
	return nil
}

// GetSubscriber は加入者を返す。Ki と OPc を含む。
func (s *Store) GetSubscriber(ctx context.Context, imsi string) (Subscriber, error) {
	subs, err := s.getSubscribers(ctx, []string{imsi})
	if err != nil {
		return Subscriber{}, err
	}
	if len(subs) == 0 {
		return Subscriber{}, ErrNotFound
	}
	return subs[0], nil
}

// getSubscribers は指定した IMSI の加入者を 1 回のパイプラインで読む。存在しないものは結果に含めない。
func (s *Store) getSubscribers(ctx context.Context, imsis []string) ([]Subscriber, error) {
	cmds := make(valkey.Commands, 0, 2*len(imsis))
	for _, imsi := range imsis {
		cmds = append(cmds,
			s.c.B().Hgetall().Key(subKey(imsi)).Build(),
			s.c.B().Smembers().Key(subClientsKey(imsi)).Build(),
		)
	}
	res := s.c.DoMulti(ctx, cmds...)

	subs := make([]Subscriber, 0, len(imsis))
	for i, imsi := range imsis {
		f, err := res[2*i].AsStrMap()
		if err != nil {
			return nil, fmt.Errorf("get subscriber: %w", err)
		}
		if len(f) == 0 {
			continue
		}
		ids, err := res[2*i+1].AsStrSlice()
		if err != nil {
			return nil, fmt.Errorf("get subscriber clients: %w", err)
		}
		sub, err := subscriberFromFields(imsi, f, ids)
		if err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, nil
}

func subscriberFromFields(imsi string, f map[string]string, clientIDs []string) (Subscriber, error) {
	sub := Subscriber{
		IMSI:           imsi,
		SQNType:        aka.SQNType(f["sqn_type"]),
		State:          State(f["state"]),
		StateChangedAt: parseTime(f["state_changed_at"]),
		CreatedAt:      parseTime(f["created_at"]),
		UpdatedAt:      parseTime(f["updated_at"]),
	}
	var err error
	if sub.Ki, sub.OPc, sub.AMF, err = decodeCredentials(f["ki"], f["opc"], f["amf"]); err != nil {
		return Subscriber{}, fmt.Errorf("subscriber %s: %w", imsi, err)
	}
	if sub.SQN, err = strconv.ParseUint(f["sqn"], 10, 64); err != nil {
		return Subscriber{}, fmt.Errorf("subscriber %s: bad sqn: %w", imsi, err)
	}
	for _, v := range clientIDs {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return Subscriber{}, fmt.Errorf("subscriber %s: bad client id %q", imsi, v)
		}
		sub.AllowedClientIDs = append(sub.AllowedClientIDs, id)
	}
	slices.Sort(sub.AllowedClientIDs)
	return sub, nil
}

// DeleteSubscriber は加入者を物理削除する。存在しなければ ErrNotFound、active なら ErrActive を返す。
func (s *Store) DeleteSubscriber(ctx context.Context, imsi string) error {
	keys := []string{subKey(imsi), subClientsKey(imsi), keySubs}
	res, err := deleteSubscriberScript.Exec(ctx, s.c, keys, []string{imsi}).ToString()
	if err != nil {
		return fmt.Errorf("delete subscriber: %w", err)
	}
	switch res {
	case "OK":
		return nil
	case "NOT_FOUND":
		return ErrNotFound
	case "ACTIVE":
		return ErrActive
	}
	return fmt.Errorf("delete subscriber: unexpected reply %q", res)
}

// 状態の変更（設計概要 §7.1）。移り方の規則を原子的に確かめる。
// terminated からの変更は、この口ではなく reinstate だけで行う。
//
// KEYS: sub:{imsi}
// ARGV: 変更後の状態, 現在日時, reinstate なら '1'
// 戻り値: {結果, 変更前の状態}。結果は OK / UNCHANGED / NOT_FOUND / NOT_ALLOWED
var setStateScript = valkey.NewLuaScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return {'NOT_FOUND', ''}
end
local cur = redis.call('HGET', KEYS[1], 'state') or ''
local to = ARGV[1]
if ARGV[3] == '1' then
  if cur ~= 'terminated' then
    return {'NOT_ALLOWED', cur}
  end
elseif cur == 'terminated' then
  if to == 'terminated' then
    return {'UNCHANGED', cur}
  end
  return {'NOT_ALLOWED', cur}
elseif cur == to then
  return {'UNCHANGED', cur}
end
redis.call('HSET', KEYS[1], 'state', to, 'state_changed_at', ARGV[2], 'updated_at', ARGV[2])
return {'OK', cur}
`)

// SetState は加入者の状態を変える。変更前の状態と、同じ状態だったか（変えなかったか）を返す。
// 加入者がなければ ErrNotFound、terminated からの変更なら ErrTransitionNotAllowed を返す。
func (s *Store) SetState(ctx context.Context, imsi string, to State) (from State, unchanged bool, err error) {
	if !to.Valid() {
		return "", false, fmt.Errorf("unknown state %q", string(to))
	}
	return s.setState(ctx, imsi, to, false)
}

// Reinstate は terminated の加入者を inactive に戻す。変更前の状態を返す。
// 加入者がなければ ErrNotFound、terminated でなければ ErrTransitionNotAllowed を返す。
func (s *Store) Reinstate(ctx context.Context, imsi string) (State, error) {
	from, _, err := s.setState(ctx, imsi, StateInactive, true)
	return from, err
}

func (s *Store) setState(ctx context.Context, imsi string, to State, reinstate bool) (State, bool, error) {
	out, err := setStateScript.Exec(ctx, s.c, []string{subKey(imsi)}, []string{string(to), now(), boolField(reinstate)}).AsStrSlice()
	if err != nil {
		return "", false, fmt.Errorf("set state: %w", err)
	}
	if len(out) != 2 {
		return "", false, fmt.Errorf("set state: unexpected reply length %d", len(out))
	}
	from := State(out[1])
	switch out[0] {
	case "OK":
		return from, false, nil
	case "UNCHANGED":
		return from, true, nil
	case "NOT_FOUND":
		return "", false, ErrNotFound
	case "NOT_ALLOWED":
		return from, false, ErrTransitionNotAllowed
	}
	return "", false, fmt.Errorf("set state: unexpected reply %q", out[0])
}

func decodeCredentials(ki, opc, amf string) (k, o []byte, a uint16, err error) {
	if k, err = hex.DecodeString(ki); err != nil || len(k) != 16 {
		return nil, nil, 0, fmt.Errorf("bad ki")
	}
	if o, err = hex.DecodeString(opc); err != nil || len(o) != 16 {
		return nil, nil, 0, fmt.Errorf("bad opc")
	}
	v, err := strconv.ParseUint(amf, 16, 16)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("bad amf")
	}
	return k, o, uint16(v), nil
}

// SubscriberPatch は加入者の変更内容。nil の項目は変更しない。
// 鍵（Ki・OPc）は登録の後に変えない（設計概要の決定事項 4）。状態は SetState と Reinstate で変える。
type SubscriberPatch struct {
	SQN              *uint64
	AMF              *uint16
	SQNType          *aka.SQNType
	AllowedClientIDs *[]int64 // 指定した場合は集合全体を置き換える
}

// terminated の加入者は変更できない（設計概要 §7.1）。
//
// KEYS: sub:{imsi}, sub:{imsi}:clients
// ARGV: 現在日時, フィールド数 n, (フィールド名, 値) × n, 許可クライアントを置き換えるか（0/1）, 許可クライアントID...
// 戻り値: 1 変更した、0 加入者がない、-1 terminated
var updateSubscriberScript = valkey.NewLuaScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
if redis.call('HGET', KEYS[1], 'state') == 'terminated' then
  return -1
end
local n = tonumber(ARGV[2])
for i = 0, n - 1 do
  redis.call('HSET', KEYS[1], ARGV[3 + 2 * i], ARGV[4 + 2 * i])
end
redis.call('HSET', KEYS[1], 'updated_at', ARGV[1])
local p = 3 + 2 * n
if ARGV[p] == '1' then
  redis.call('DEL', KEYS[2])
  for i = p + 1, #ARGV do
    redis.call('SADD', KEYS[2], ARGV[i])
  end
end
return 1
`)

// UpdateSubscriber は加入者の指定された項目だけを変更する。
// 加入者がなければ ErrNotFound、terminated なら ErrTerminated、存在しないクライアントID があれば ErrUnknownClient を返す。
func (s *Store) UpdateSubscriber(ctx context.Context, imsi string, p SubscriberPatch) error {
	var fields []string
	if p.SQN != nil {
		fields = append(fields, "sqn", strconv.FormatUint(*p.SQN&aka.SQNMask, 10))
	}
	if p.AMF != nil {
		fields = append(fields, "amf", fmt.Sprintf("%04x", *p.AMF))
	}
	if p.SQNType != nil {
		if !p.SQNType.Valid() {
			return fmt.Errorf("unknown SQN type %q", string(*p.SQNType))
		}
		fields = append(fields, "sqn_type", string(*p.SQNType))
	}

	args := []string{now(), strconv.Itoa(len(fields) / 2)}
	args = append(args, fields...)
	if p.AllowedClientIDs == nil {
		args = append(args, "0")
	} else {
		if err := s.checkClientsExist(ctx, *p.AllowedClientIDs); err != nil {
			return err
		}
		args = append(args, "1")
		for _, id := range *p.AllowedClientIDs {
			args = append(args, strconv.FormatInt(id, 10))
		}
	}

	keys := []string{subKey(imsi), subClientsKey(imsi)}
	n, err := updateSubscriberScript.Exec(ctx, s.c, keys, args).AsInt64()
	if err != nil {
		return fmt.Errorf("update subscriber: %w", err)
	}
	switch n {
	case 0:
		return ErrNotFound
	case -1:
		return ErrTerminated
	}
	return nil
}

// SubscriberPage は加入者一覧の 1 ページ。
type SubscriberPage struct {
	Items []Subscriber
	// Total は prefix に一致する加入者の総数。
	Total int64
	// NextCursor は次のページの開始位置。次のページがなければ空。
	NextCursor string
}

// ListSubscribers は IMSI の辞書順で加入者を返す。
// prefix が空でなければ IMSI の前方一致で絞り込む。cursor には前のページの NextCursor を渡す。
func (s *Store) ListSubscribers(ctx context.Context, prefix, cursor string, limit int) (SubscriberPage, error) {
	lo, hi := "-", "+"
	if prefix != "" {
		// IMSI は数字だけなので、prefix に続く文字はすべて 0xff より小さい。
		lo, hi = "["+prefix, "["+prefix+"\xff"
	}
	start := lo
	if cursor != "" {
		start = "(" + cursor
	}

	res := s.c.DoMulti(ctx,
		s.c.B().Zlexcount().Key(keySubs).Min(lo).Max(hi).Build(),
		// 次のページがあるかを知るために 1 件多く読む。
		s.c.B().Zrange().Key(keySubs).Min(start).Max(hi).Bylex().Limit(0, int64(limit)+1).Build(),
	)
	total, err := res[0].AsInt64()
	if err != nil {
		return SubscriberPage{}, fmt.Errorf("list subscribers: %w", err)
	}
	imsis, err := res[1].AsStrSlice()
	if err != nil {
		return SubscriberPage{}, fmt.Errorf("list subscribers: %w", err)
	}

	page := SubscriberPage{Total: total}
	if len(imsis) > limit {
		imsis = imsis[:limit]
		page.NextCursor = imsis[limit-1]
	}
	// 一覧の取得後に削除された加入者は、ここで結果から抜ける。
	if page.Items, err = s.getSubscribers(ctx, imsis); err != nil {
		return SubscriberPage{}, err
	}
	return page, nil
}

// CountSubscribers は加入者の総数を返す。
func (s *Store) CountSubscribers(ctx context.Context) (int64, error) {
	n, err := s.c.Do(ctx, s.c.B().Zcard().Key(keySubs).Build()).AsInt64()
	if err != nil {
		return 0, fmt.Errorf("count subscribers: %w", err)
	}
	return n, nil
}
