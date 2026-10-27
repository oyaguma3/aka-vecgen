package main

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/audit"
	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/config"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

// AV クライアントとサーバー証明書の登録・変更・削除は、ノードの上のコマンドで行う（設計概要 §9.3、確認事項 E5）。
// 管理API は読み出しだけにする。コマンドの操作は監査ログに残す（操作者は -operator、既定 cli）。

const (
	maxClientNameLen  = 64
	maxNetworkNameLen = 255
	// purgeTimeout は、削除したクライアントを各加入者の許可クライアントから取り除く処理の上限時間。
	purgeTimeout = 5 * time.Minute
	// selfSignedValidFor は作り直す自己署名サーバー証明書の有効期間（serve が初めに作るものと同じ）。
	selfSignedValidFor = 10 * 365 * 24 * time.Hour
	// reloadNotice は、動いている serve に反映するための案内。
	reloadNotice = "to apply it to the running server: docker compose kill -s HUP aka-vecgen"
)

// cliAudit はコマンドの操作を監査ログ（Stream と日ごとのファイル）に残す。
type cliAudit struct {
	rec      *audit.Recorder
	operator string
}

func newCLIAudit(cfg config.Config, st *store.Store, operator string) cliAudit {
	// 監査ログの書き出しの失敗だけを標準エラーに出す（"audit" の行は出さない）
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return cliAudit{
		rec:      &audit.Recorder{Stream: st, MaxLen: cfg.AuditMaxLen, Files: audit.NewFiles(cfg.AuditDir, cfg.AuditRetentionDays), Log: log},
		operator: operator,
	}
}

func (a cliAudit) record(ctx context.Context, action, target string, detail any) {
	e := store.AuditEntry{Operator: a.operator, MgmtClient: "cli", Action: action, Target: target}
	if detail != nil {
		b, _ := json.Marshal(detail)
		e.Detail = string(b)
	}
	a.rec.Record(ctx, e)
}

// operatorFlag は監査ログに残す操作者の名前のフラグを足す。
func operatorFlag(fs *flag.FlagSet) *string {
	return fs.String("operator", "cli", "監査ログに残す操作者の名前")
}

// openForCommand は Valkey に接続し、監査ログの書き手を作る。
func openForCommand(ctx context.Context, operator string) (config.Config, *store.Store, cliAudit, error) {
	cfg, st, err := openStore(ctx)
	if err != nil {
		return config.Config{}, nil, cliAudit{}, err
	}
	return cfg, st, newCLIAudit(cfg, st, operator), nil
}

type change struct {
	From any `json:"from"`
	To   any `json:"to"`
}

func readPEMFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func clientCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: aka-vecgen client add|list|show|update|replace-cert|del|gen-cert [options]")
	}
	fs := flag.NewFlagSet("client "+args[0], flag.ExitOnError)

	switch args[0] {
	case "add":
		name := fs.String("name", "", "表示名")
		certFile := fs.String("cert", "-", "クライアント証明書の PEM ファイル（- は標準入力）")
		networkName := fs.String("network-name", "", "EAP-AKA' の Network Name（空なら WLAN）")
		operator := operatorFlag(fs)
		fs.Parse(args[1:])
		if *name == "" || len(*name) > maxClientNameLen {
			return fmt.Errorf("-name is required (up to %d characters)", maxClientNameLen)
		}
		if len(*networkName) > maxNetworkNameLen {
			return fmt.Errorf("-network-name must be up to %d characters", maxNetworkNameLen)
		}
		data, err := readPEMFile(*certFile)
		if err != nil {
			return fmt.Errorf("read certificate: %w", err)
		}
		cert, err := certs.ParsePEM(data)
		if err != nil {
			return err
		}
		if err := certs.CheckValidity(cert); err != nil {
			return err
		}
		_, st, a, err := openForCommand(ctx, *operator)
		if err != nil {
			return err
		}
		defer st.Close()
		c, err := st.CreateClient(ctx, store.NewClient{Name: *name, Cert: cert, Enabled: true, NetworkName: *networkName})
		if err != nil {
			return err
		}
		a.record(ctx, "client.create", fmt.Sprint(c.ID), map[string]any{
			"name": c.Name, "fingerprintSha256": c.Fingerprint, "notAfter": c.NotAfter, "enabled": c.Enabled, "networkName": c.NetworkName,
		})
		fmt.Printf("client %d added (name=%s fingerprint=%s not-after=%s)\n",
			c.ID, c.Name, c.Fingerprint, c.NotAfter.Format(time.RFC3339))
		return nil

	case "list":
		fs.Parse(args[1:])
		_, st, err := openStore(ctx)
		if err != nil {
			return err
		}
		defer st.Close()
		clients, err := st.ListClients(ctx)
		if err != nil {
			return err
		}
		for _, c := range clients {
			fmt.Printf("%d\tname=%s\tenabled=%t\tnetwork-name=%q\tnot-after=%s\tfingerprint=%s\n",
				c.ID, c.Name, c.Enabled, c.NetworkName, c.NotAfter.Format(time.RFC3339), c.Fingerprint)
		}
		return nil

	case "show":
		id := fs.Int64("id", 0, "クライアントID")
		fs.Parse(args[1:])
		_, st, err := openStore(ctx)
		if err != nil {
			return err
		}
		defer st.Close()
		c, err := st.GetClient(ctx, *id)
		if err != nil {
			return err
		}
		fmt.Printf("id:            %d\n", c.ID)
		fmt.Printf("name:          %s\n", c.Name)
		fmt.Printf("enabled:       %t\n", c.Enabled)
		fmt.Printf("network-name:  %q\n", c.NetworkName)
		fmt.Printf("fingerprint:   %s\n", c.Fingerprint)
		fmt.Printf("not-after:     %s\n", c.NotAfter.Format(time.RFC3339))
		fmt.Printf("created-at:    %s\n", c.CreatedAt.Format(time.RFC3339))
		return nil

	case "update":
		id := fs.Int64("id", 0, "クライアントID")
		name := fs.String("name", "", "表示名")
		enable := fs.Bool("enable", false, "有効にする")
		disable := fs.Bool("disable", false, "無効にする（以後の接続と払い出しを断る）")
		networkName := fs.String("network-name", "", "EAP-AKA' の Network Name（空にすると既定の WLAN）")
		operator := operatorFlag(fs)
		fs.Parse(args[1:])
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		var patch store.ClientPatch
		if set["name"] {
			if *name == "" || len(*name) > maxClientNameLen {
				return fmt.Errorf("-name must be 1 to %d characters", maxClientNameLen)
			}
			patch.Name = name
		}
		switch {
		case *enable && *disable:
			return errors.New("-enable and -disable cannot be used together")
		case *enable:
			patch.Enabled = new(true)
		case *disable:
			patch.Enabled = new(false)
		}
		if set["network-name"] {
			if len(*networkName) > maxNetworkNameLen {
				return fmt.Errorf("-network-name must be up to %d characters", maxNetworkNameLen)
			}
			patch.NetworkName = networkName
		}
		if patch.Name == nil && patch.Enabled == nil && patch.NetworkName == nil {
			return errors.New("nothing to update: use -name, -enable, -disable or -network-name")
		}
		_, st, a, err := openForCommand(ctx, *operator)
		if err != nil {
			return err
		}
		defer st.Close()
		before, err := st.GetClient(ctx, *id)
		if err != nil {
			return err
		}
		if err := st.UpdateClient(ctx, *id, patch); err != nil {
			return err
		}
		detail := map[string]change{}
		if patch.Name != nil {
			detail["name"] = change{before.Name, *patch.Name}
		}
		if patch.Enabled != nil {
			detail["enabled"] = change{before.Enabled, *patch.Enabled}
		}
		if patch.NetworkName != nil {
			detail["networkName"] = change{before.NetworkName, *patch.NetworkName}
		}
		a.record(ctx, "client.update", fmt.Sprint(*id), detail)
		fmt.Printf("client %d updated\n", *id)
		return nil

	case "replace-cert":
		id := fs.Int64("id", 0, "クライアントID")
		certFile := fs.String("cert", "-", "新しいクライアント証明書の PEM ファイル（- は標準入力）")
		operator := operatorFlag(fs)
		fs.Parse(args[1:])
		data, err := readPEMFile(*certFile)
		if err != nil {
			return fmt.Errorf("read certificate: %w", err)
		}
		cert, err := certs.ParsePEM(data)
		if err != nil {
			return err
		}
		if err := certs.CheckValidity(cert); err != nil {
			return err
		}
		_, st, a, err := openForCommand(ctx, *operator)
		if err != nil {
			return err
		}
		defer st.Close()
		before, err := st.GetClient(ctx, *id)
		if err != nil {
			return err
		}
		if err := st.ReplaceClientCertificate(ctx, *id, cert); err != nil {
			return err
		}
		a.record(ctx, "client.certificate.replace", fmt.Sprint(*id), map[string]any{
			"fingerprintSha256": change{before.Fingerprint, certs.Fingerprint(cert)}, "notAfter": cert.NotAfter,
		})
		fmt.Printf("client %d certificate replaced (fingerprint=%s not-after=%s)\n", *id, certs.Fingerprint(cert), cert.NotAfter.Format(time.RFC3339))
		return nil

	case "del":
		id := fs.Int64("id", 0, "クライアントID")
		operator := operatorFlag(fs)
		fs.Parse(args[1:])
		_, st, a, err := openForCommand(ctx, *operator)
		if err != nil {
			return err
		}
		defer st.Close()
		c, err := st.GetClient(ctx, *id)
		if err != nil {
			return err
		}
		if err := st.DeleteClient(ctx, *id); err != nil {
			return err
		}
		a.record(ctx, "client.delete", fmt.Sprint(*id), map[string]any{"name": c.Name, "fingerprintSha256": c.Fingerprint})
		pctx, cancel := context.WithTimeout(ctx, purgeTimeout)
		defer cancel()
		if err := st.PurgeClientFromSubscribers(pctx, *id); err != nil {
			return fmt.Errorf("client %d was deleted, but removing it from subscribers failed (run del again): %w", *id, err)
		}
		fmt.Printf("client %d deleted\n", *id)
		return nil

	case "gen-cert":
		name := fs.String("name", "", "証明書の CommonName")
		days := fs.Int("days", 825, "有効日数")
		outCert := fs.String("out-cert", "", "証明書の出力先（省略時は標準出力）")
		outKey := fs.String("out-key", "", "秘密鍵の出力先（省略時は標準出力）")
		fs.Parse(args[1:])
		if *name == "" {
			return errors.New("-name is required")
		}
		certPEM, keyPEM, err := certs.SelfSigned(certs.SelfSignedOptions{
			CommonName: *name,
			Client:     true,
			ValidFor:   time.Duration(*days) * 24 * time.Hour,
		})
		if err != nil {
			return err
		}
		if err := writeOutput(*outCert, certPEM, 0o644); err != nil {
			return err
		}
		return writeOutput(*outKey, keyPEM, 0o600)
	}
	return fmt.Errorf("unknown client command %q", args[0])
}

// showCertCommand は保存されているサーバー証明書を PEM で表示する。
func showCertCommand(ctx context.Context, slot store.CertSlot) error {
	_, st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	c, err := st.ServerCertificate(ctx, slot)
	if errors.Is(err, store.ErrNotFound) {
		return errors.New("server certificate has not been generated yet; start the server once")
	}
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(c.CertPEM)
	return err
}

// avCertCommand は AV 用のサーバー証明書を表示・差し替え・作り直しする。
// 差し替えと作り直しは、動いている serve には SIGHUP で反映する（確認事項 E1）。
func avCertCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return showCertCommand(ctx, store.CertSlotAV)
	}
	fs := flag.NewFlagSet("av-cert "+args[0], flag.ExitOnError)
	switch args[0] {
	case "replace":
		certFile := fs.String("cert", "", "サーバー証明書の PEM ファイル")
		keyFile := fs.String("key", "", "秘密鍵の PEM ファイル")
		operator := operatorFlag(fs)
		fs.Parse(args[1:])
		if *certFile == "" || *keyFile == "" {
			return errors.New("-cert and -key are required")
		}
		certPEM, err := os.ReadFile(*certFile)
		if err != nil {
			return err
		}
		keyPEM, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		return setServerCert(ctx, store.CertSlotAV, certPEM, keyPEM, store.CertSourceUploaded, *operator, "av-server-certificate.replace")
	case "reset":
		operator := operatorFlag(fs)
		fs.Parse(args[1:])
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		certPEM, keyPEM, err := certs.SelfSigned(certs.SelfSignedOptions{CommonName: "aka-vecgen", Hosts: cfg.AVTLSHosts, ValidFor: selfSignedValidFor})
		if err != nil {
			return err
		}
		return setServerCert(ctx, store.CertSlotAV, certPEM, keyPEM, store.CertSourceSelfSigned, *operator, "av-server-certificate.reset")
	}
	return fmt.Errorf("unknown av-cert command %q", args[0])
}

// adminCertCommand は管理API 用のサーバー証明書を表示・作り直しする（今の VECGEN_ADMIN_TLS_HOSTS で）。
func adminCertCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return showCertCommand(ctx, store.CertSlotAdmin)
	}
	if args[0] != "reset" {
		return fmt.Errorf("unknown admin-cert command %q", args[0])
	}
	fs := flag.NewFlagSet("admin-cert reset", flag.ExitOnError)
	operator := operatorFlag(fs)
	fs.Parse(args[1:])
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := certs.SelfSigned(certs.SelfSignedOptions{CommonName: "aka-vecgen", Hosts: cfg.AdminTLSHosts, ValidFor: selfSignedValidFor})
	if err != nil {
		return err
	}
	return setServerCert(ctx, store.CertSlotAdmin, certPEM, keyPEM, store.CertSourceSelfSigned, *operator, "admin-server-certificate.reset")
}

// setServerCert はサーバー証明書を確かめて保存し、監査ログに残して、証明書を標準出力に出す。
func setServerCert(ctx context.Context, slot store.CertSlot, certPEM, keyPEM []byte, source, operator, action string) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("%w: %v", certs.ErrInvalid, err)
	}
	if err := certs.CheckValidity(cert.Leaf); err != nil {
		return err
	}
	_, st, a, err := openForCommand(ctx, operator)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.SetServerCertificate(ctx, slot, certPEM, keyPEM, source); err != nil {
		return err
	}
	a.record(ctx, action, string(slot), map[string]any{
		"source": source, "fingerprintSha256": certs.Fingerprint(cert.Leaf), "notAfter": cert.Leaf.NotAfter,
	})
	fmt.Fprintf(os.Stderr, "server certificate %s saved (fingerprint=%s not-after=%s); %s\n",
		slot, certs.Fingerprint(cert.Leaf), cert.Leaf.NotAfter.Format(time.RFC3339), reloadNotice)
	_, err = os.Stdout.Write(certPEM)
	return err
}
