// Package store は Valkey 上の加入者・クライアント・証明書データを扱う。
// キー設計は docs/data-model.md を参照。
package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
)

var (
	// ErrNotFound は対象の加入者またはクライアントが存在しないことを表す。
	ErrNotFound = errors.New("not found")
	// ErrExists は同じ IMSI の加入者が既に存在することを表す。
	ErrExists = errors.New("already exists")
	// ErrForbidden は、クライアントがその加入者の払い出しを許可されていないことを表す。
	ErrForbidden = errors.New("forbidden")
	// ErrClientDisabled は、クライアントが無効にされたか削除されたことを表す。
	ErrClientDisabled = errors.New("client disabled")
	// ErrInactive は、加入者が inactive で払い出せないことを表す。
	ErrInactive = errors.New("subscriber inactive")
	// ErrTerminated は、加入者が terminated で払い出せない（変更もできない）ことを表す。
	ErrTerminated = errors.New("subscriber terminated")
	// ErrActive は、加入者が active で物理削除できないことを表す。
	ErrActive = errors.New("subscriber active")
	// ErrTransitionNotAllowed は、状態の移り方の規則で許されない変更であることを表す。
	ErrTransitionNotAllowed = errors.New("state transition not allowed")
	// ErrNetworkNameMismatch は要求された Network Name がサーバー側の設定値と一致しないことを表す。
	ErrNetworkNameMismatch = errors.New("network name mismatch")
	// ErrCertRegistered は同じ証明書が既に登録されていることを表す。
	ErrCertRegistered = errors.New("certificate already registered")
	// ErrUnknownClient は存在しないクライアントID が指定されたことを表す。
	ErrUnknownClient = errors.New("unknown client id")
)

const (
	keySubs      = "subs"
	keyClients   = "clients"
	keyClientSeq = "seq:client"
	keyAVTLS     = "cfg:av_tls"
)

func subKey(imsi string) string        { return "sub:" + imsi }
func subClientsKey(imsi string) string { return "sub:" + imsi + ":clients" }
func clientKey(id int64) string        { return "client:" + strconv.FormatInt(id, 10) }
func clientFPKey(fp string) string     { return "clientfp:" + fp }

// Store は Valkey への接続を持つ。
type Store struct {
	c valkey.Client
}

// Options は Valkey への接続設定。
type Options struct {
	Addr     string // host:port
	Password string
	// DB は使用する論理データベースの番号。通常は 0。
	DB int
}

// Open は Valkey に接続し、疎通を確認する。
func Open(ctx context.Context, o Options) (*Store, error) {
	c, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{o.Addr},
		Password:    o.Password,
		SelectDB:    o.DB,
		ClientName:  "aka-vecgen",
		// 単一ノード前提で、クライアント側キャッシュは使わない。
		DisableCache: true,
	})
	if err != nil {
		return nil, fmt.Errorf("connect valkey %s: %w", o.Addr, err)
	}
	s := &Store{c: c}
	if err := c.Do(ctx, c.B().Ping().Build()).Error(); err != nil {
		c.Close()
		return nil, fmt.Errorf("ping valkey %s: %w", o.Addr, err)
	}
	return s, nil
}

// Close は接続を閉じる。
func (s *Store) Close() { s.c.Close() }

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func parseTime(v string) time.Time {
	t, _ := time.Parse(time.RFC3339, v)
	return t
}

func boolField(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
