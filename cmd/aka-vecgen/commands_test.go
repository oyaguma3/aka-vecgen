package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/kek"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

// コマンドの結合試験。実際の Valkey に接続する（論理データベース 0 番の全データを消すので、専用の Valkey を使う）。
//
//	VECGEN_TEST_VALKEY_ADDR=127.0.0.1:16379 go test ./cmd/aka-vecgen/
func setupCommands(t *testing.T) (dir string) {
	t.Helper()
	addr := os.Getenv("VECGEN_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("VECGEN_TEST_VALKEY_ADDR is not set")
	}
	password := os.Getenv("VECGEN_TEST_VALKEY_PASSWORD")
	raw, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, Password: password, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.Do(t.Context(), raw.B().Flushdb().Build()).Error(); err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	if _, err := kek.GenerateFile(filepath.Join(dir, "kek")); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"VECGEN_VALKEY_ADDR": addr, "VECGEN_VALKEY_PASSWORD": password, "VECGEN_KEK_FILE": filepath.Join(dir, "kek"),
		"VECGEN_AUDIT_DIR": filepath.Join(dir, "audit"), "VECGEN_AV_TLS_HOSTS": "localhost", "VECGEN_ADMIN_TLS_HOSTS": "localhost",
		"VECGEN_AUDIT_MAX": "", "VECGEN_AUDIT_RETENTION_DAYS": "", "VECGEN_LOG_LEVEL": "",
	} {
		t.Setenv(k, v)
	}
	if err := os.MkdirAll(filepath.Join(dir, "audit"), 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeCert は自己署名の証明書と秘密鍵をファイルに書き、パスを返す。
func writeCert(t *testing.T, dir, name string, client bool) (certFile, keyFile string) {
	t.Helper()
	c, k, err := certs.SelfSigned(certs.SelfSignedOptions{CommonName: name, Client: client, Hosts: []string{"localhost"}, ValidFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
	if err := os.WriteFile(certFile, c, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, k, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func openTest(t *testing.T) *store.Store {
	t.Helper()
	_, st, err := openStore(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

func TestClientCommands(t *testing.T) {
	dir := setupCommands(t)
	ctx := t.Context()
	cert1, _ := writeCert(t, dir, "radius", true)
	cert2, _ := writeCert(t, dir, "radius-new", true)

	run := func(args ...string) error {
		t.Helper()
		return clientCommand(ctx, args)
	}
	if err := run("add", "-name", "radius", "-cert", cert1, "-operator", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := run("update", "-id", "1", "-disable", "-network-name", "WLAN", "-operator", "alice"); err != nil {
		t.Fatal(err)
	}
	st := openTest(t)
	c, err := st.GetClient(ctx, 1)
	if err != nil || c.Enabled || c.NetworkName != "WLAN" {
		t.Fatalf("after update: %+v, %v", c, err)
	}
	if err := run("update", "-id", "1", "-enable", "-name", "radius-1"); err != nil {
		t.Fatal(err)
	}
	if err := run("replace-cert", "-id", "1", "-cert", cert2); err != nil {
		t.Fatal(err)
	}
	if c, _ := st.GetClient(ctx, 1); !c.Enabled || c.Name != "radius-1" || c.CertPEM == "" {
		t.Errorf("after enable and replace: %+v", c)
	}
	if err := run("show", "-id", "1"); err != nil {
		t.Error(err)
	}
	if err := run("list"); err != nil {
		t.Error(err)
	}
	// 変えるものがない、-enable と -disable を一緒に、は誤り
	if err := run("update", "-id", "1"); err == nil {
		t.Error("update without changes: want error")
	}
	if err := run("update", "-id", "1", "-enable", "-disable"); err == nil {
		t.Error("update with -enable and -disable: want error")
	}
	if err := run("del", "-id", "1", "-operator", "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetClient(ctx, 1); err == nil {
		t.Error("client 1 still exists")
	}

	entries, _, err := st.ListAudit(ctx, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range slices.Backward(entries) {
		actions = append(actions, e.Action+"/"+e.Operator+"/"+e.MgmtClient)
	}
	want := []string{"client.create/alice/cli", "client.update/alice/cli", "client.update/cli/cli", "client.certificate.replace/cli/cli", "client.delete/bob/cli"}
	if !slices.Equal(actions, want) {
		t.Errorf("audit = %v, want %v", actions, want)
	}
	// 日ごとのファイルにも残る
	files, _ := filepath.Glob(filepath.Join(dir, "audit", "audit-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("audit files = %v", files)
	}
	data, _ := os.ReadFile(files[0])
	if n := strings.Count(string(data), "\n"); n != len(want) {
		t.Errorf("audit file has %d lines, want %d", n, len(want))
	}
}

func TestCertAndSubscriberCommands(t *testing.T) {
	dir := setupCommands(t)
	ctx := t.Context()
	certFile, keyFile := writeCert(t, dir, "localhost", false)
	_, otherKey := writeCert(t, dir, "other", false)

	if err := avCertCommand(ctx, []string{"replace", "-cert", certFile, "-key", keyFile}); err != nil {
		t.Fatal(err)
	}
	// 秘密鍵が証明書と対応していなければ断る
	if err := avCertCommand(ctx, []string{"replace", "-cert", certFile, "-key", otherKey}); err == nil {
		t.Error("replace with a mismatched key: want error")
	}
	if err := avCertCommand(ctx, nil); err != nil {
		t.Error(err)
	}
	if err := avCertCommand(ctx, []string{"reset"}); err != nil {
		t.Fatal(err)
	}
	if err := adminCertCommand(ctx, []string{"reset", "-operator", "carol"}); err != nil {
		t.Fatal(err)
	}
	if err := subscriberCommand(ctx, []string{"add", "-imsi", "001010000000001", "-ki", "465b5ce8b199b49faa5f0a2ee238a6bc",
		"-opc", "cd63cb71954a9f4e48a5994e37a02baf", "-state", "terminated"}); err != nil {
		t.Fatal(err)
	}
	if err := subscriberCommand(ctx, []string{"del", "-imsi", "001010000000001"}); err != nil {
		t.Fatal(err)
	}

	// KEK の入れ替えも監査ログに残る
	newKEK := filepath.Join(dir, "kek-new")
	if _, err := kek.GenerateFile(newKEK); err != nil {
		t.Fatal(err)
	}
	if err := rotateKEKCommand(ctx, []string{"-old", filepath.Join(dir, "kek"), "-new", newKEK, "-operator", "dave"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VECGEN_KEK_FILE", newKEK)
	st := openTest(t)
	entries, _, err := st.ListAudit(ctx, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range slices.Backward(entries) {
		actions = append(actions, e.Action+"/"+e.Operator)
	}
	want := []string{"av-server-certificate.replace/cli", "av-server-certificate.reset/cli", "admin-server-certificate.reset/carol",
		"subscriber.create/cli", "subscriber.state/cli", "subscriber.delete/cli", "kek.rotate/dave"}
	if !slices.Equal(actions, want) {
		t.Errorf("audit = %v, want %v", actions, want)
	}
	if _, err := st.ServerCertificate(ctx, store.CertSlotAdmin); err != nil {
		t.Errorf("admin certificate after rotation: %v", err)
	}
}
