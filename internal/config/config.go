// Package config は環境変数から設定を読み込む。
package config

import (
	"cmp"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Config はサーバーの設定。
type Config struct {
	// ValkeyAddr は Valkey の接続先（host:port）。
	ValkeyAddr string
	// ValkeyPassword は Valkey のパスワード。
	ValkeyPassword string
	// KEKFile は加入者の鍵とサーバー証明書の秘密鍵を暗号化する KEK のファイル（設計概要 §8.1）。
	KEKFile string

	// AVTLSAddr は認証ベクターAPI の mTLS リスナーの待ち受けアドレス。
	AVTLSAddr string
	// AVTLSHosts は、AV 用の自己署名サーバー証明書を生成するときに SAN へ入れるホスト名と IP アドレス。
	AVTLSHosts []string

	// AdminAddr は管理API の待ち受けアドレス。
	AdminAddr string
	// AdminTLSHosts は、管理API 用の自己署名サーバー証明書を生成するときに SAN へ入れるホスト名と IP アドレス。
	AdminTLSHosts []string
	// AdminClientsFile は管理クライアントのピンのファイル（1 行に 識別名=フィンガープリント。設計概要 §10.1）。
	// ファイルがなければ管理API を起動しない。SIGHUP で読み直す。
	AdminClientsFile string
	// KeyExport は鍵の読み出しの口（GET /admin/v2/subscribers/{imsi}/keys）を有効にするか（設計概要 §8.4）。
	KeyExport bool

	// LogLevel はログの出力レベル。
	LogLevel slog.Level
	// AuditMaxLen は監査ログの Stream の保持件数の上限。
	AuditMaxLen int64
	// AuditDir は監査ログの日ごとのファイル（audit-YYYYMMDD.jsonl）の置き場所。空なら書かない（設計概要 §13.2）。
	AuditDir string
	// AuditRetentionDays は監査ログのファイルをノードで持つ日数。
	AuditRetentionDays int
}

// Load は環境変数から設定を読み込む。
func Load() (Config, error) {
	c := Config{
		ValkeyAddr:       cmp.Or(os.Getenv("VECGEN_VALKEY_ADDR"), "valkey:6379"),
		ValkeyPassword:   os.Getenv("VECGEN_VALKEY_PASSWORD"),
		KEKFile:          cmp.Or(os.Getenv("VECGEN_KEK_FILE"), "/run/secrets/kek"),
		AVTLSAddr:        cmp.Or(os.Getenv("VECGEN_AV_TLS_ADDR"), ":8443"),
		AVTLSHosts:       splitList(cmp.Or(os.Getenv("VECGEN_AV_TLS_HOSTS"), "localhost,127.0.0.1")),
		AdminAddr:        cmp.Or(os.Getenv("VECGEN_ADMIN_ADDR"), ":9443"),
		AdminTLSHosts:    splitList(cmp.Or(os.Getenv("VECGEN_ADMIN_TLS_HOSTS"), "localhost,127.0.0.1")),
		AdminClientsFile: cmp.Or(os.Getenv("VECGEN_ADMIN_CLIENTS_FILE"), "/run/secrets/admin-clients"),
		AuditDir:         cmp.Or(os.Getenv("VECGEN_AUDIT_DIR"), "/data/audit"),
	}
	if v := os.Getenv("VECGEN_KEY_EXPORT"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("VECGEN_KEY_EXPORT: must be true or false")
		}
		c.KeyExport = b
	}
	if v := os.Getenv("VECGEN_LOG_LEVEL"); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			return Config{}, fmt.Errorf("VECGEN_LOG_LEVEL: %w", err)
		}
	}
	var err error
	if c.AuditMaxLen, err = positiveInt("VECGEN_AUDIT_MAX", 100000); err != nil {
		return Config{}, err
	}
	days, err := positiveInt("VECGEN_AUDIT_RETENTION_DAYS", 14)
	if err != nil {
		return Config{}, err
	}
	c.AuditRetentionDays = int(days)
	return c, nil
}

func positiveInt(name string, def int64) (int64, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s: must be a positive integer", name)
	}
	return n, nil
}

var (
	adminClientNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	fingerprintPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// AdminClients は管理クライアントのピン。証明書のフィンガープリント（SHA-256、16進小文字）から識別名を引く。
type AdminClients map[string]string

// Names は識別名を重ねずに辞書順で返す。
func (a AdminClients) Names() []string {
	var names []string
	for _, n := range a {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return names
}

// LoadAdminClients は管理クライアントのピンのファイルを読む（設計概要 §10.1）。
func LoadAdminClients(path string) (AdminClients, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a, err := ParseAdminClients(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return a, nil
}

// ParseAdminClients はピンのファイルの中身を解釈する。1 行に「識別名=フィンガープリント」を書く。
// # で始まる行と空行は無視する。フィンガープリントは SHA-256 の 16 進で、大文字やコロン区切り（openssl の出力形式）も受け付ける。
// 同じ識別名を 2 行以上書ける（証明書の入れ替えの間は新旧の両方を受ける）。同じフィンガープリントが 2 回出たら誤り。
func ParseAdminClients(v string) (AdminClients, error) {
	clients := AdminClients{}
	for i, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, fp, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !ok || !adminClientNamePattern.MatchString(name) {
			return nil, fmt.Errorf("line %d: want <name>=<sha256 fingerprint>", i+1)
		}
		fp = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
		if !fingerprintPattern.MatchString(fp) {
			return nil, fmt.Errorf("line %d: bad fingerprint for %q: want 64 hex digits", i+1, name)
		}
		if other, dup := clients[fp]; dup {
			return nil, fmt.Errorf("line %d: fingerprint of %q is already used by %q", i+1, name, other)
		}
		clients[fp] = name
	}
	return clients, nil
}

func splitList(v string) []string {
	var out []string
	for part := range strings.SplitSeq(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
