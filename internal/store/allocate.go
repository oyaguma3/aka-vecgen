package store

import (
	"context"
	"fmt"
	"strconv"

	"github.com/valkey-io/valkey-go"

	"github.com/oyaguma3/aka-vecgen/internal/aka"
)

// Allocation は SQN の払い出し結果。
type Allocation struct {
	Base        uint64 // 加算前の SQN。各ベクターの SQN は SQNType.Sequence(Base, n) で求める
	Credentials aka.Credentials
	SQNType     aka.SQNType
	NetworkName string // EAP-AKA' の鍵導出に使う Network Name
}

// 許可判定と SQN の更新を原子的に行う。仕様は docs/data-model.md の 4.2 を参照。
//
// 判定の順は認証ベクターAPI の契約 §9.2 のとおり。加入者に依らない検査（ネットワーク名）を先に行い、
// 加入者に依る検査（有無・クライアントの有効・許可・状態）はどれも拒否の理由だけを返す。
// 呼び出し側はそれらを同じ一般的な拒否にする。
//
// KEYS: sub:{imsi}, sub:{imsi}:clients, client:{id}
// ARGV:
//
//	[1] クライアントID
//	[2] 生成数 n。0 なら SQN を進めずに現在の値を返す
//	[3] 再同期で置き換える SQN。通常時は空文字列
//	[4] 要求された Network Name（anId）。空文字列なら照合しない（EAP-AKA' 以外）
//	[5] Network Name の既定値
var allocateScript = valkey.NewLuaScript(`
local sub = KEYS[1]
local c = redis.call('HMGET', KEYS[3], 'enabled', 'network_name')
local network_name = ARGV[5]
if c[2] and c[2] ~= '' then
  network_name = c[2]
end
if ARGV[4] ~= '' and ARGV[4] ~= network_name then
  return {'NETWORK_NAME_MISMATCH'}
end

if redis.call('EXISTS', sub) == 0 then
  return {'NOT_FOUND'}
end
if c[1] ~= '1' then
  return {'CLIENT_DISABLED'}
end
if redis.call('SISMEMBER', KEYS[2], ARGV[1]) == 0 then
  return {'FORBIDDEN'}
end
local f = redis.call('HMGET', sub, 'sqn', 'cred', 'cred_kek', 'amf', 'sqn_type', 'state')
if f[6] == 'terminated' then
  return {'TERMINATED'}
end
if f[6] ~= 'active' then
  return {'INACTIVE'}
end

local base = tonumber(f[1])
if ARGV[3] ~= '' then
  base = tonumber(ARGV[3])
end

local n = tonumber(ARGV[2])
local adv = 0
if n > 0 then
  if f[5] == 'inc1' then
    adv = n
  elseif f[5] == 'inc32' then
    adv = 32 * n
  elseif f[5] == 'inc33' then
    adv = 33 + 32 * (n - 1)
  else
    return {'BAD_SQN_TYPE'}
  end
end
if n > 0 or ARGV[3] ~= '' then
  redis.call('HSET', sub, 'sqn', string.format('%.0f', (base + adv) % 281474976710656))
end

return {'OK', string.format('%.0f', base), f[2] or '', f[3] or '', f[4], f[5], network_name}
`)

// AllocateRequest は SQN の払い出し要求。
type AllocateRequest struct {
	IMSI string
	// ClientID は mTLS で識別したクライアントID。
	ClientID int64
	// N は生成数。0 なら SQN を進めずに現在の値と鍵情報だけを返す。
	N int
	// ResyncSQN は再同期で置き換える SQN（SQN_MS）。通常時は nil。
	ResyncSQN *uint64
	// NetworkName は要求された Network Name。空でなければサーバー側の設定値と照合する。
	NetworkName string
	// DefaultNetworkName は、クライアントに Network Name が設定されていない場合の値。
	DefaultNetworkName string
}

// Allocate は加入者への払い出しが許可されているかを確認し、SQN を N 個分進める。
// Network Name が一致しなければ ErrNetworkNameMismatch（加入者を調べる前に判定する）、
// 加入者がなければ ErrNotFound、クライアントが無効なら ErrClientDisabled、許可されていなければ ErrForbidden、
// 加入者が inactive なら ErrInactive、terminated なら ErrTerminated を返す。
func (s *Store) Allocate(ctx context.Context, req AllocateRequest) (Allocation, error) {
	keys := []string{subKey(req.IMSI), subClientsKey(req.IMSI), clientKey(req.ClientID)}
	clientID := strconv.FormatInt(req.ClientID, 10)
	resync := ""
	if req.ResyncSQN != nil {
		resync = strconv.FormatUint(*req.ResyncSQN&aka.SQNMask, 10)
	}
	args := []string{clientID, strconv.Itoa(req.N), resync, req.NetworkName, req.DefaultNetworkName}

	out, err := allocateScript.Exec(ctx, s.c, keys, args).AsStrSlice()
	if err != nil {
		return Allocation{}, fmt.Errorf("allocate: %w", err)
	}
	if len(out) == 0 {
		return Allocation{}, fmt.Errorf("allocate: empty reply")
	}
	switch out[0] {
	case "OK":
	case "NOT_FOUND":
		return Allocation{}, ErrNotFound
	case "CLIENT_DISABLED":
		return Allocation{}, ErrClientDisabled
	case "FORBIDDEN":
		return Allocation{}, ErrForbidden
	case "INACTIVE":
		return Allocation{}, ErrInactive
	case "TERMINATED":
		return Allocation{}, ErrTerminated
	case "NETWORK_NAME_MISMATCH":
		return Allocation{}, ErrNetworkNameMismatch
	default:
		return Allocation{}, fmt.Errorf("allocate: subscriber %s: %s", req.IMSI, out[0])
	}
	if len(out) != 7 {
		return Allocation{}, fmt.Errorf("allocate: unexpected reply length %d", len(out))
	}

	a := Allocation{SQNType: aka.SQNType(out[5]), NetworkName: out[6]}
	if a.Base, err = strconv.ParseUint(out[1], 10, 64); err != nil {
		return Allocation{}, fmt.Errorf("allocate: subscriber %s: bad sqn: %w", req.IMSI, err)
	}
	// 鍵は要求ごとに復号する（設計概要 §8.1）。平文の行・別の KEK の行は ErrCredInvalid（確認事項 D1）
	if a.Credentials.Ki, a.Credentials.OPc, err = s.openCred(req.IMSI, out[2], out[3]); err != nil {
		return Allocation{}, fmt.Errorf("allocate: subscriber %s: %w", req.IMSI, err)
	}
	if a.Credentials.AMF, err = parseAMF(out[4]); err != nil {
		return Allocation{}, fmt.Errorf("allocate: subscriber %s: %w", req.IMSI, err)
	}
	return a, nil
}
