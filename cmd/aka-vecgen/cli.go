package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/aka"
	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

var imsiPattern = regexp.MustCompile(`^[0-9]{5,15}$`)

func subscriberCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: aka-vecgen subscriber add|show|del [options]")
	}
	fs := flag.NewFlagSet("subscriber "+args[0], flag.ExitOnError)
	imsi := fs.String("imsi", "", "IMSI（5〜15 桁の数字）")

	switch args[0] {
	case "add":
		ki := fs.String("ki", "", "Ki（16進 32 桁）")
		opc := fs.String("opc", "", "OPc（16進 32 桁）")
		sqn := fs.String("sqn", "000000000000", "SQN の初期値（16進 12 桁）")
		amf := fs.String("amf", "8000", "AMF（16進 4 桁）")
		sqnType := fs.String("sqn-type", string(aka.SQNInc32), "SQN 増加タイプ（inc1 / inc32 / inc33）")
		state := fs.String("state", string(store.StateActive), "状態（active / inactive / terminated。terminated は inactive で登録してから変える）")
		clients := fs.String("clients", "", "許可クライアントID（カンマ区切り）")
		fs.Parse(args[1:])

		sub := store.Subscriber{IMSI: *imsi, SQNType: aka.SQNType(*sqnType), State: store.State(*state)}
		if !imsiPattern.MatchString(sub.IMSI) {
			return errors.New("-imsi must be 5 to 15 digits")
		}
		if !sub.State.Valid() {
			return errors.New("-state must be active, inactive or terminated")
		}
		terminate := sub.State == store.StateTerminated
		if terminate {
			sub.State = store.StateInactive
		}
		var err error
		if sub.Ki, err = hexBytes("-ki", *ki, 16); err != nil {
			return err
		}
		if sub.OPc, err = hexBytes("-opc", *opc, 16); err != nil {
			return err
		}
		sqnBytes, err := hexBytes("-sqn", *sqn, 6)
		if err != nil {
			return err
		}
		for _, b := range sqnBytes {
			sub.SQN = sub.SQN<<8 | uint64(b)
		}
		amfBytes, err := hexBytes("-amf", *amf, 2)
		if err != nil {
			return err
		}
		sub.AMF = uint16(amfBytes[0])<<8 | uint16(amfBytes[1])
		if !sub.SQNType.Valid() {
			return errors.New("-sqn-type must be inc1, inc32 or inc33")
		}
		for part := range strings.SplitSeq(*clients, ",") {
			if part = strings.TrimSpace(part); part == "" {
				continue
			}
			id, err := strconv.ParseInt(part, 10, 64)
			if err != nil || id < 1 {
				return fmt.Errorf("-clients: bad client id %q", part)
			}
			sub.AllowedClientIDs = append(sub.AllowedClientIDs, id)
		}

		_, st, err := openStore(ctx)
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.CreateSubscriber(ctx, sub); err != nil {
			return err
		}
		if terminate {
			if _, _, err := st.SetState(ctx, sub.IMSI, store.StateTerminated); err != nil {
				return fmt.Errorf("subscriber %s was added as inactive, but setting it terminated failed: %w", sub.IMSI, err)
			}
			sub.State = store.StateTerminated
		}
		fmt.Printf("subscriber %s added (state=%s)\n", sub.IMSI, sub.State)
		return nil

	case "show":
		fs.Parse(args[1:])
		_, st, err := openStore(ctx)
		if err != nil {
			return err
		}
		defer st.Close()
		sub, err := st.GetSubscriber(ctx, *imsi)
		if err != nil {
			return err
		}
		// Ki と OPc は表示しない。
		fmt.Printf("imsi:        %s\n", sub.IMSI)
		fmt.Printf("state:       %s\n", sub.State)
		fmt.Printf("sqn:         %012x\n", sub.SQN)
		fmt.Printf("amf:         %04x\n", sub.AMF)
		fmt.Printf("sqn-type:    %s\n", sub.SQNType)
		fmt.Printf("clients:     %v\n", sub.AllowedClientIDs)
		fmt.Printf("created-at:  %s\n", sub.CreatedAt.Format(time.RFC3339))
		return nil

	case "del":
		fs.Parse(args[1:])
		_, st, err := openStore(ctx)
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.DeleteSubscriber(ctx, *imsi); err != nil {
			return err
		}
		fmt.Printf("subscriber %s deleted\n", *imsi)
		return nil
	}
	return fmt.Errorf("unknown subscriber command %q", args[0])
}

func clientCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: aka-vecgen client add|list|del|gen-cert [options]")
	}
	fs := flag.NewFlagSet("client "+args[0], flag.ExitOnError)

	switch args[0] {
	case "add":
		name := fs.String("name", "", "表示名")
		certFile := fs.String("cert", "-", "クライアント証明書の PEM ファイル（- は標準入力）")
		networkName := fs.String("network-name", "", "EAP-AKA' の Network Name（空なら WLAN）")
		fs.Parse(args[1:])
		if *name == "" {
			return errors.New("-name is required")
		}
		var data []byte
		var err error
		if *certFile == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(*certFile)
		}
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

		_, st, err := openStore(ctx)
		if err != nil {
			return err
		}
		defer st.Close()
		c, err := st.CreateClient(ctx, store.NewClient{Name: *name, Cert: cert, Enabled: true, NetworkName: *networkName})
		if err != nil {
			return err
		}
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

	case "del":
		id := fs.Int64("id", 0, "クライアントID")
		fs.Parse(args[1:])
		_, st, err := openStore(ctx)
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.DeleteClient(ctx, *id); err != nil {
			return err
		}
		if err := st.PurgeClientFromSubscribers(ctx, *id); err != nil {
			return err
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

func adminCertCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return showCertCommand(ctx, store.CertSlotAdmin)
	}
	if args[0] != "reset" {
		return fmt.Errorf("unknown admin-cert command %q", args[0])
	}
	// 現在の VECGEN_ADMIN_TLS_HOSTS で自己署名証明書を作り直す。反映にはサーバーの再起動が必要。
	cfg, st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	certPEM, keyPEM, err := certs.SelfSigned(certs.SelfSignedOptions{
		CommonName: "aka-vecgen",
		Hosts:      cfg.AdminTLSHosts,
		ValidFor:   10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	if err := st.SetServerCertificate(ctx, store.CertSlotAdmin, certPEM, keyPEM, store.CertSourceSelfSigned); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "admin server certificate regenerated; restart the server to apply")
	_, err = os.Stdout.Write(certPEM)
	return err
}

func fingerprintCommand() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	cert, err := certs.ParsePEM(data)
	if err != nil {
		return err
	}
	fmt.Println(certs.Fingerprint(cert))
	return nil
}

func hexBytes(name, v string, size int) ([]byte, error) {
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("%s must be %d hex digits", name, size*2)
	}
	return b, nil
}

func writeOutput(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, perm)
}
