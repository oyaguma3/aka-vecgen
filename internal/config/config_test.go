package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseAdminClients(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	fp2 := strings.Repeat("cd", 32)
	colons := strings.ToUpper(strings.Join(strings.Split(strings.Repeat("ab ", 32), " ")[:32], ":"))

	got, err := ParseAdminClients("# provisioner\nprov=" + fp + "\n\n ops = " + fp2 + " \n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[fp] != "prov" || got[fp2] != "ops" {
		t.Errorf("got %v", got)
	}

	// 同じ識別名に新旧 2 つのフィンガープリント（証明書の入れ替えの間）
	got, err = ParseAdminClients("prov=" + fp + "\nprov=" + fp2)
	if err != nil || got[fp] != "prov" || got[fp2] != "prov" {
		t.Errorf("two fingerprints: got %v, err %v", got, err)
	}
	if names := got.Names(); !slices.Equal(names, []string{"prov"}) {
		t.Errorf("Names() = %v", names)
	}

	// openssl の出力形式（大文字、コロン区切り）も受け付ける。
	got, err = ParseAdminClients("prov=" + colons)
	if err != nil || got[fp] != "prov" {
		t.Errorf("colon form: got %v, err %v", got, err)
	}

	if got, err := ParseAdminClients("# only a comment\n"); err != nil || len(got) != 0 {
		t.Errorf("empty: got %v, err %v", got, err)
	}

	for _, bad := range []string{
		fp,                                 // 識別名がない
		"prov=" + fp[:10],                  // 短い
		"p rov=" + fp,                      // 識別名に空白
		"a=" + fp + "\nb=" + fp,            // 同じフィンガープリント
		"prov=" + strings.Repeat("zz", 32), // 16進でない
		"a=" + fp + ",b=" + fp2,            // 1 行に 2 つ（カンマ区切りは使えない）
	} {
		if _, err := ParseAdminClients(bad); err == nil {
			t.Errorf("ParseAdminClients(%q): want error", bad)
		}
	}
}

func TestLoadAdminClients(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-clients")
	if _, err := LoadAdminClients(path); !os.IsNotExist(err) {
		t.Errorf("missing file: err = %v, want not exist", err)
	}
	if err := os.WriteFile(path, []byte("prov="+strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadAdminClients(path); err != nil || len(got) != 1 {
		t.Errorf("LoadAdminClients = %v, %v", got, err)
	}
}

func TestLoad(t *testing.T) {
	// 呼び出したシェルの環境変数に左右されないよう、関係する変数を空にする（空は既定の値の意味）
	for _, k := range []string{"VECGEN_KEY_EXPORT", "VECGEN_AUDIT_DIR", "VECGEN_AUDIT_MAX", "VECGEN_AUDIT_RETENTION_DAYS", "VECGEN_ADMIN_CLIENTS_FILE"} {
		t.Setenv(k, "")
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyExport || c.AuditMaxLen != 100000 || c.AuditDir != "/data/audit" || c.AuditRetentionDays != 14 ||
		c.AdminClientsFile != "/run/secrets/admin-clients" {
		t.Errorf("defaults = %+v", c)
	}
	t.Setenv("VECGEN_KEY_EXPORT", "true")
	t.Setenv("VECGEN_AUDIT_DIR", "/tmp/audit")
	if c, err := Load(); err != nil || !c.KeyExport || c.AuditDir != "/tmp/audit" {
		t.Errorf("Load = %+v, %v", c, err)
	}
	t.Setenv("VECGEN_KEY_EXPORT", "yes")
	if _, err := Load(); err == nil {
		t.Error("VECGEN_KEY_EXPORT=yes: want error")
	}
}
