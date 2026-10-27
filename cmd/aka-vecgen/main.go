// aka-vecgen は Milenage による AKA 認証ベクターを払い出す API サーバー。
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
	"uuid"

	"github.com/oyaguma3/aka-vecgen/internal/adminapi"
	"github.com/oyaguma3/aka-vecgen/internal/config"
	"github.com/oyaguma3/aka-vecgen/internal/logbuf"
	"github.com/oyaguma3/aka-vecgen/internal/server"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

// version はビルド時に -ldflags "-X main.version=..." で埋め込む。
var version = "dev"

const usage = `usage: aka-vecgen <command>

commands:
  serve                     サーバーを起動する（コマンド省略時の既定）
  subscriber add|show|del   加入者を登録・表示・削除する
  client add|list|del       AVクライアントを登録・一覧・削除する
  client gen-cert           クライアント用の自己署名証明書と秘密鍵を生成する
  av-cert                   認証ベクターAPI 用のサーバー証明書を表示する
  admin-cert [reset]        管理API 用のサーバー証明書を表示する（reset は再生成）
  fingerprint               標準入力の証明書（PEM）の SHA-256 フィンガープリントを表示する
  healthcheck               動いているサーバーのリスナーに接続できるかを確かめる（compose の healthcheck 用）

各コマンドのオプションは -h で確認できる。
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"serve"}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch args[0] {
	case "serve":
		err = serve(ctx)
	case "subscriber":
		err = subscriberCommand(ctx, args[1:])
	case "client":
		err = clientCommand(ctx, args[1:])
	case "av-cert":
		err = showCertCommand(ctx, store.CertSlotAV)
	case "admin-cert":
		err = adminCertCommand(ctx, args[1:])
	case "fingerprint":
		err = fingerprintCommand()
	case "healthcheck":
		err = healthcheckCommand(ctx)
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// openStore は設定を読み込んで Valkey に接続する。
func openStore(ctx context.Context) (config.Config, *store.Store, error) {
	cfg, err := config.Load()
	if err != nil {
		return config.Config{}, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := store.Open(ctx, store.Options{Addr: cfg.ValkeyAddr, Password: cfg.ValkeyPassword})
	if err != nil {
		return config.Config{}, nil, err
	}
	return cfg, st, nil
}

func serve(ctx context.Context) error {
	cfg, st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	// ログは標準出力に出しつつ、管理API で返すために直近分をメモリにも保持する。
	logs := logbuf.New(cfg.LogBuffer)
	log := slog.New(logs.Handler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel})))

	srv, err := server.New(ctx, cfg, st, log)
	if err != nil {
		return err
	}
	admin := &adminapi.Handler{
		Store:          st,
		Certs:          srv,
		Logs:           logs,
		Log:            log.With("listener", "admin"),
		MgmtClient:     srv.AdminClientName,
		Version:        version,
		BootID:         uuid.New().String(),
		StartedAt:      time.Now().UTC(),
		AVPlainEnabled: cfg.AVPlainAddr != "",
		AuditMaxLen:    cfg.AuditMaxLen,
	}
	log.Info("starting", "version", version, "boot_id", admin.BootID)
	return srv.Run(ctx, admin.Routes())
}
