package store

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/oyaguma3/aka-vecgen/internal/certs"
)

// Client は AVクライアント（認証ベクターAPI のクライアント）。
type Client struct {
	ID          int64
	Name        string
	CertPEM     string
	Fingerprint string // 証明書（DER）の SHA-256。16進小文字
	NotAfter    time.Time
	Enabled     bool
	NetworkName string // 空なら既定値を使う
	CreatedAt   time.Time
}

// KEYS: clientfp:{fp}, client:{id}, clients
// ARGV: id, name, cert_pem, fp_sha256, not_after, enabled, network_name, created_at
var createClientScript = valkey.NewLuaScript(`
if redis.call('SET', KEYS[1], ARGV[1], 'NX') == false then
  return 0
end
redis.call('HSET', KEYS[2],
  'name', ARGV[2], 'cert_pem', ARGV[3], 'fp_sha256', ARGV[4], 'not_after', ARGV[5],
  'enabled', ARGV[6], 'network_name', ARGV[7], 'created_at', ARGV[8])
redis.call('ZADD', KEYS[3], ARGV[1], ARGV[1])
return 1
`)

// KEYS: client:{id}, clientfp:{fp}, clients
// ARGV: id
var deleteClientScript = valkey.NewLuaScript(`
local n = redis.call('DEL', KEYS[1])
redis.call('DEL', KEYS[2])
redis.call('ZREM', KEYS[3], ARGV[1])
return n
`)

// NewClient は登録する AVクライアントの内容。
type NewClient struct {
	Name        string
	Cert        *x509.Certificate
	Enabled     bool
	NetworkName string
}

// CreateClient は AVクライアントを登録し、クライアントID を発番する。
// 同じ証明書が既に登録されていれば ErrCertRegistered を返す。
func (s *Store) CreateClient(ctx context.Context, nc NewClient) (Client, error) {
	// ID は再利用しない。登録に失敗した場合もその番号は欠番にする。
	id, err := s.c.Do(ctx, s.c.B().Incr().Key(keyClientSeq).Build()).AsInt64()
	if err != nil {
		return Client{}, fmt.Errorf("create client: %w", err)
	}
	c := Client{
		ID:          id,
		Name:        nc.Name,
		CertPEM:     certPEM(nc.Cert),
		Fingerprint: certs.Fingerprint(nc.Cert),
		NotAfter:    nc.Cert.NotAfter.UTC().Truncate(time.Second),
		Enabled:     nc.Enabled,
		NetworkName: nc.NetworkName,
		CreatedAt:   parseTime(now()),
	}
	idStr := strconv.FormatInt(id, 10)
	keys := []string{clientFPKey(c.Fingerprint), clientKey(id), keyClients}
	args := []string{
		idStr, c.Name, c.CertPEM, c.Fingerprint, c.NotAfter.Format(time.RFC3339),
		boolField(c.Enabled), c.NetworkName, c.CreatedAt.Format(time.RFC3339),
	}
	created, err := createClientScript.Exec(ctx, s.c, keys, args).AsInt64()
	if err != nil {
		return Client{}, fmt.Errorf("create client: %w", err)
	}
	if created == 0 {
		return Client{}, ErrCertRegistered
	}
	return c, nil
}

func certPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// GetClient は AVクライアントを返す。
func (s *Store) GetClient(ctx context.Context, id int64) (Client, error) {
	f, err := s.c.Do(ctx, s.c.B().Hgetall().Key(clientKey(id)).Build()).AsStrMap()
	if err != nil {
		return Client{}, fmt.Errorf("get client: %w", err)
	}
	if len(f) == 0 {
		return Client{}, ErrNotFound
	}
	return clientFromFields(id, f), nil
}

func clientFromFields(id int64, f map[string]string) Client {
	return Client{
		ID:          id,
		Name:        f["name"],
		CertPEM:     f["cert_pem"],
		Fingerprint: f["fp_sha256"],
		NotAfter:    parseTime(f["not_after"]),
		Enabled:     f["enabled"] == "1",
		NetworkName: f["network_name"],
		CreatedAt:   parseTime(f["created_at"]),
	}
}

// ClientByFingerprint は証明書のフィンガープリントから AVクライアントを引く。
// 登録されていなければ ErrNotFound を返す。
func (s *Store) ClientByFingerprint(ctx context.Context, fp string) (Client, error) {
	id, err := s.c.Do(ctx, s.c.B().Get().Key(clientFPKey(fp)).Build()).AsInt64()
	if valkey.IsValkeyNil(err) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, fmt.Errorf("lookup client: %w", err)
	}
	return s.GetClient(ctx, id)
}

// ListClients は AVクライアントをクライアントID の昇順で全件返す。
func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	ids, err := s.c.Do(ctx, s.c.B().Zrange().Key(keyClients).Min("0").Max("-1").Build()).AsStrSlice()
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	clients := make([]Client, 0, len(ids))
	for _, v := range ids {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("list clients: bad id %q", v)
		}
		c, err := s.GetClient(ctx, id)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, nil
}

// DeleteClient は AVクライアントを削除する。
// 削除した時点でそのクライアントは接続できなくなる。
// 各加入者の許可クライアントからの除去は PurgeClientFromSubscribers で行う。
func (s *Store) DeleteClient(ctx context.Context, id int64) error {
	c, err := s.GetClient(ctx, id)
	if err != nil {
		return err
	}
	keys := []string{clientKey(id), clientFPKey(c.Fingerprint), keyClients}
	n, err := deleteClientScript.Exec(ctx, s.c, keys, []string{strconv.FormatInt(id, 10)}).AsInt64()
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// purgeBatch は PurgeClientFromSubscribers が 1 回のパイプラインで処理する加入者数。
const purgeBatch = 500

// PurgeClientFromSubscribers は、全加入者の許可クライアントから id を取り除く。
// クライアントID は再利用しないので、これが終わる前でも別のクライアントが許可されることはない。
func (s *Store) PurgeClientFromSubscribers(ctx context.Context, id int64) error {
	idStr := strconv.FormatInt(id, 10)
	min := "-"
	for {
		imsis, err := s.c.Do(ctx, s.c.B().Zrange().Key(keySubs).Min(min).Max("+").Bylex().Limit(0, purgeBatch).Build()).AsStrSlice()
		if err != nil {
			return fmt.Errorf("purge client %d: %w", id, err)
		}
		if len(imsis) == 0 {
			return nil
		}
		cmds := make(valkey.Commands, len(imsis))
		for i, imsi := range imsis {
			cmds[i] = s.c.B().Srem().Key(subClientsKey(imsi)).Member(idStr).Build()
		}
		for _, r := range s.c.DoMulti(ctx, cmds...) {
			if err := r.Error(); err != nil {
				return fmt.Errorf("purge client %d: %w", id, err)
			}
		}
		min = "(" + imsis[len(imsis)-1]
	}
}

// ClientPatch は AVクライアントの変更内容。nil の項目は変更しない。
type ClientPatch struct {
	Name        *string
	Enabled     *bool
	NetworkName *string
}

// KEYS: client:{id}
// ARGV: (フィールド名, 値)...
var updateClientScript = valkey.NewLuaScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
for i = 1, #ARGV, 2 do
  redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
end
return 1
`)

// UpdateClient は AVクライアントの指定された項目だけを変更する。
func (s *Store) UpdateClient(ctx context.Context, id int64, p ClientPatch) error {
	var args []string
	if p.Name != nil {
		args = append(args, "name", *p.Name)
	}
	if p.Enabled != nil {
		args = append(args, "enabled", boolField(*p.Enabled))
	}
	if p.NetworkName != nil {
		args = append(args, "network_name", *p.NetworkName)
	}
	n, err := updateClientScript.Exec(ctx, s.c, []string{clientKey(id)}, args).AsInt64()
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// 古い clientfp:{fp} はスクリプト内でキー名を組み立てて消す。単一ノード前提なので問題ない。
//
// KEYS: client:{id}, clientfp:{新しい fp}
// ARGV: id, cert_pem, fp_sha256, not_after
var replaceClientCertScript = valkey.NewLuaScript(`
local old = redis.call('HGET', KEYS[1], 'fp_sha256')
if not old then
  return 0
end
local owner = redis.call('GET', KEYS[2])
if owner and owner ~= ARGV[1] then
  return -1
end
if old ~= ARGV[3] then
  redis.call('DEL', 'clientfp:' .. old)
end
redis.call('SET', KEYS[2], ARGV[1])
redis.call('HSET', KEYS[1], 'cert_pem', ARGV[2], 'fp_sha256', ARGV[3], 'not_after', ARGV[4])
return 1
`)

// ReplaceClientCertificate は、クライアントID を変えずに証明書だけを差し替える。
// 同じ証明書が別のクライアントに登録されていれば ErrCertRegistered を返す。
func (s *Store) ReplaceClientCertificate(ctx context.Context, id int64, cert *x509.Certificate) error {
	fp := certs.Fingerprint(cert)
	args := []string{
		strconv.FormatInt(id, 10), certPEM(cert), fp,
		cert.NotAfter.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	n, err := replaceClientCertScript.Exec(ctx, s.c, []string{clientKey(id), clientFPKey(fp)}, args).AsInt64()
	if err != nil {
		return fmt.Errorf("replace client certificate: %w", err)
	}
	switch n {
	case 0:
		return ErrNotFound
	case -1:
		return ErrCertRegistered
	}
	return nil
}

// ClientIDs は登録されているクライアントID を昇順で返す。
func (s *Store) ClientIDs(ctx context.Context) ([]int64, error) {
	ids, err := s.c.Do(ctx, s.c.B().Zrange().Key(keyClients).Min("0").Max("-1").Build()).AsStrSlice()
	if err != nil {
		return nil, fmt.Errorf("list client ids: %w", err)
	}
	out := make([]int64, len(ids))
	for i, v := range ids {
		if out[i], err = strconv.ParseInt(v, 10, 64); err != nil {
			return nil, fmt.Errorf("list client ids: bad id %q", v)
		}
	}
	return out, nil
}

// CountClients は AVクライアントの総数を返す。
func (s *Store) CountClients(ctx context.Context) (int64, error) {
	n, err := s.c.Do(ctx, s.c.B().Zcard().Key(keyClients).Build()).AsInt64()
	if err != nil {
		return 0, fmt.Errorf("count clients: %w", err)
	}
	return n, nil
}
