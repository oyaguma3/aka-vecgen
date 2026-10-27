// aka-vecgen は Milenage による AKA 認証ベクターを払い出す API サーバー。
package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
	"uuid"

	"github.com/oyaguma3/aka-vecgen/internal/adminapi"
	"github.com/oyaguma3/aka-vecgen/internal/audit"
	"github.com/oyaguma3/aka-vecgen/internal/config"
	"github.com/oyaguma3/aka-vecgen/internal/kek"
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
  client add|list|show|update|replace-cert|del
                            AVクライアントを登録・一覧・表示・変更（名前・有効と無効・Network Name）・証明書の差し替え・削除する
  client gen-cert           クライアント用の自己署名証明書と秘密鍵を生成する
  av-cert [replace|reset]   認証ベクターAPI 用のサーバー証明書を表示・差し替え・作り直しする
  admin-cert [reset]        管理API 用のサーバー証明書を表示・作り直しする

登録・変更・削除は監査ログに残す（-operator で操作者の名前を付けられる。既定 cli）。
サーバー証明書の差し替えと作り直し、管理クライアントのピンのファイルの変更は、
動いている serve に SIGHUP で反映する（docker compose kill -s HUP aka-vecgen）。
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
		err = avCertCommand(ctx, args[1:])
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
	cfg, err := config.Load()
	if err != nil {
		return config.Config{}, nil, err
	}
	st, _, err := openStoreWith(ctx, cfg)
	return cfg, st, err
}

func openStoreWith(ctx context.Context, cfg config.Config) (*store.Store, bool, error) {
	k, err := kek.Load(cfg.KEKFile)
	if err != nil {
		return nil, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := store.Open(ctx, store.Options{Addr: cfg.ValkeyAddr, Password: cfg.ValkeyPassword})
	if err != nil {
		return nil, false, err
	}
	initialized, err := st.SetupKEK(ctx, k)
	if err != nil {
		st.Close()
		return nil, false, fmt.Errorf("kek %s (%s): %w", k.ID(), cfg.KEKFile, err)
	}
	return st, initialized, nil
}

// startupEventID は起動の失敗のログの event_id を返す（設計概要 §13.1）。
func startupEventID(err error) string {
	switch {
	case errors.Is(err, store.ErrKEKMismatch):
		return "KEK_MISMATCH"
	case errors.Is(err, store.ErrKEKMissing):
		return "KEK_MISSING"
	case errors.Is(err, store.ErrKEKRotationInProgress):
		return "KEK_ROTATION_IN_PROGRESS"
	}
	return "STARTUP_ERR"
}

func serve(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	fail := func(err error) error {
		log.Error("failed to start", "event_id", startupEventID(err), "error", err)
		return err
	}

	st, kekInitialized, err := openStoreWith(ctx, cfg)
	if err != nil {
		return fail(err)
	}
	defer st.Close()

	// 監査ログの日ごとのファイル（設計概要 §13.2）。置き場所に書けなければ起動しない
	files := audit.NewFiles(cfg.AuditDir, cfg.AuditRetentionDays)
	if files != nil {
		if err := checkWritableDir(cfg.AuditDir); err != nil {
			return fail(fmt.Errorf("audit dir: %w", err))
		}
		if err := files.Maintain(time.Now()); err != nil {
			log.Warn("failed to maintain audit files", "event_id", "AUDIT_MAINTAIN_ERR", "error", err)
		}
	}
	rec := &audit.Recorder{Stream: st, MaxLen: cfg.AuditMaxLen, Files: files, Log: log}

	srv, err := server.New(ctx, cfg, st, log)
	if err != nil {
		return fail(err)
	}
	admin := &adminapi.Handler{
		Store:      st,
		Server:     srv,
		Audit:      rec,
		Log:        log.With("listener", "admin"),
		MgmtClient: srv.AdminClientName,
		KeyExport:  cfg.KeyExport,
		Version:    version,
		BootID:     uuid.New().String(),
		StartedAt:  time.Now().UTC(),
	}
	log.Info("starting", "event_id", "STARTING", "version", version, "boot_id", admin.BootID, "kek_id", st.KEKID(),
		"kek_initialized", kekInitialized, "admin_api", srv.AdminEnabled(), "key_export", cfg.KeyExport, "audit_dir", cfg.AuditDir)
	if cfg.KeyExport {
		log.Warn("key export is enabled (VECGEN_KEY_EXPORT=true); disable it when the work is done", "event_id", "KEY_EXPORT_ENABLED")
	}

	// 動いている印を書き続ける（rotate-kek は、これがあると断る。確認事項 D3）。監査ログのファイルは 1 時間ごとに整える
	if err := st.MarkServing(ctx, admin.BootID); err != nil {
		return fail(err)
	}
	go func() {
		alive := time.NewTicker(store.ServeAliveInterval)
		defer alive.Stop()
		maintain := time.NewTicker(time.Hour)
		defer maintain.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-alive.C:
				if err := st.MarkServing(ctx, admin.BootID); err != nil && ctx.Err() == nil {
					log.Warn("failed to mark serving", "event_id", "SERVE_MARK_ERR", "error", err)
				}
			case <-maintain.C:
				if files != nil {
					if err := files.Maintain(time.Now()); err != nil {
						log.Warn("failed to maintain audit files", "event_id", "AUDIT_MAINTAIN_ERR", "error", err)
					}
				}
			}
		}
	}()
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = st.ClearServing(cctx, admin.BootID)
	}()

	// SIGHUP で、管理クライアントのピンとサーバー証明書を読み直す（確認事項 E1）
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				res, err := srv.Reload(ctx)
				detail := map[string]any{"adminClients": res.AdminClients, "avCertChanged": res.AVCertChanged, "adminCertChanged": res.AdminCertChanged}
				if err != nil {
					detail["error"] = err.Error()
				}
				b, _ := json.Marshal(detail)
				rec.Record(ctx, store.AuditEntry{Operator: "sighup", MgmtClient: "", Action: "reload", Target: "aka-vecgen", Detail: string(b)})
			}
		}
	}()
	return srv.Run(ctx, admin.Routes())
}

// checkWritableDir は、ディレクトリを作り（なければ）、書けることを確かめる。
// compose でホストのディレクトリをマウントしたとき、UID 65532 で書けないまま動き出すのを防ぐ。
func checkWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".write-check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
