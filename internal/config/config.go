// Package config は環境変数から設定を読み込む。
package config

import (
	"cmp"
	"fmt"
	"log/slog"
	"os"
	"regexp"
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
	// AdminClients は管理クライアント。証明書のフィンガープリント（SHA-256、16進小文字）から識別名を引く。
	// 空なら管理API を起動しない。
	AdminClients map[string]string

	// LogLevel はログの出力レベル。
	LogLevel slog.Level
	// LogBuffer は管理API で返すためにメモリに保持するログの件数。
	LogBuffer int
	// AuditMaxLen は監査ログの保持件数の上限。
	AuditMaxLen int64
}

// Load は環境変数から設定を読み込む。
func Load() (Config, error) {
	c := Config{
		ValkeyAddr:     cmp.Or(os.Getenv("VECGEN_VALKEY_ADDR"), "valkey:6379"),
		ValkeyPassword: os.Getenv("VECGEN_VALKEY_PASSWORD"),
		KEKFile:        cmp.Or(os.Getenv("VECGEN_KEK_FILE"), "/run/secrets/kek"),
		AVTLSAddr:      cmp.Or(os.Getenv("VECGEN_AV_TLS_ADDR"), ":8443"),
		AVTLSHosts:     splitList(cmp.Or(os.Getenv("VECGEN_AV_TLS_HOSTS"), "localhost,127.0.0.1")),
		AdminAddr:      cmp.Or(os.Getenv("VECGEN_ADMIN_ADDR"), ":9443"),
		AdminTLSHosts:  splitList(cmp.Or(os.Getenv("VECGEN_ADMIN_TLS_HOSTS"), "localhost,127.0.0.1")),
	}
	if v := os.Getenv("VECGEN_LOG_LEVEL"); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			return Config{}, fmt.Errorf("VECGEN_LOG_LEVEL: %w", err)
		}
	}
	var err error
	if c.AdminClients, err = ParseAdminClients(os.Getenv("VECGEN_ADMIN_CLIENTS")); err != nil {
		return Config{}, fmt.Errorf("VECGEN_ADMIN_CLIENTS: %w", err)
	}
	logBuffer, err := positiveInt("VECGEN_LOG_BUFFER", 1000)
	if err != nil {
		return Config{}, err
	}
	c.LogBuffer = int(logBuffer)
	if c.AuditMaxLen, err = positiveInt("VECGEN_AUDIT_MAX", 10000); err != nil {
		return Config{}, err
	}
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

// ParseAdminClients は「識別名=フィンガープリント」のカンマ区切りを解釈する。
// フィンガープリントは SHA-256 の 16進表記で、大文字やコロン区切り（openssl の出力形式）も受け付ける。
func ParseAdminClients(v string) (map[string]string, error) {
	clients := map[string]string{}
	for _, entry := range splitList(v) {
		name, fp, ok := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		if !ok || !adminClientNamePattern.MatchString(name) {
			return nil, fmt.Errorf("bad entry %q: want <name>=<sha256 fingerprint>", entry)
		}
		fp = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
		if !fingerprintPattern.MatchString(fp) {
			return nil, fmt.Errorf("bad fingerprint for %q: want 64 hex digits", name)
		}
		if other, dup := clients[fp]; dup {
			return nil, fmt.Errorf("fingerprint of %q is already used by %q", name, other)
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
