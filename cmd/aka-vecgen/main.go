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
	"github.com/oyaguma3/aka-vecgen/internal/kek"
	"github.com/oyaguma3/aka-vecgen/internal/logbuf"
	"github.com/oyaguma3/aka-vecgen/internal/server"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

// version はビルド時に -ldflags "-X main.version=..." で埋め込む。
var version = "dev"

const usage = `usage: aka-vecgen <command>

commands:
  serve                     サーバーを起動する（コマンド省略時の既定）
  gen-kek [-out ファイル]   KEK（鍵を暗号化する鍵）を作る（-out を省くと標準出力）
  rotate-kek -old F -new F  加入者の鍵とサーバー証明書の秘密鍵を新しい KEK で暗号化し直す（serve を止めて行う）
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
	case "gen-kek":
		err = genKEKCommand(args[1:])
	case "rotate-kek":
		err = rotateKEKCommand(ctx, args[1:])
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

// openStore は設定を読み込んで Valkey に接続し、KEK を確かめる（設計概要 §8.2）。
// KEK のファイルを読めない・形が違う・Valkey の識別子と合わない、rotate-kek の途中、のどれかなら失敗する。
// 初めての起動（cfg:kek がなく、暗号化したデータもない）なら KEK の識別子を書く。
func openStore(ctx context.Context) (config.Config, *store.Store, error) {
	cfg, st, _, err := openStoreKEK(ctx)
	return cfg, st, err
}

func openStoreKEK(ctx context.Context) (config.Config, *store.Store, bool, error) {
	cfg, err := config.Load()
	if err != nil {
		return config.Config{}, nil, false, err
	}
	k, err := kek.Load(cfg.KEKFile)
	if err != nil {
		return config.Config{}, nil, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := store.Open(ctx, store.Options{Addr: cfg.ValkeyAddr, Password: cfg.ValkeyPassword})
	if err != nil {
		return config.Config{}, nil, false, err
	}
	initialized, err := st.SetupKEK(ctx, k)
	if err != nil {
		st.Close()
		return config.Config{}, nil, false, fmt.Errorf("kek %s (%s): %w", k.ID(), cfg.KEKFile, err)
	}
	return cfg, st, initialized, nil
}

func serve(ctx context.Context) error {
	cfg, st, kekInitialized, err := openStoreKEK(ctx)
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
		Store:       st,
		Certs:       srv,
		Logs:        logs,
		Log:         log.With("listener", "admin"),
		MgmtClient:  srv.AdminClientName,
		Version:     version,
		BootID:      uuid.New().String(),
		StartedAt:   time.Now().UTC(),
		AuditMaxLen: cfg.AuditMaxLen,
	}
	log.Info("starting", "version", version, "boot_id", admin.BootID, "kek_id", st.KEKID(), "kek_initialized", kekInitialized)

	// 動いている印を書き続ける（rotate-kek は、これがあると断る。確認事項 D3）
	if err := st.MarkServing(ctx, admin.BootID); err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(store.ServeAliveInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.MarkServing(ctx, admin.BootID); err != nil && ctx.Err() == nil {
					log.Warn("failed to mark serving", "error", err)
				}
			}
		}
	}()
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = st.ClearServing(cctx, admin.BootID)
	}()
	return srv.Run(ctx, admin.Routes())
}
