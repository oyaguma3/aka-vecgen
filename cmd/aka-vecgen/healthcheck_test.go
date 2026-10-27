package main

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/oyaguma3/aka-vecgen/internal/config"
)

func TestListenerAddrs(t *testing.T) {
	pins := filepath.Join(t.TempDir(), "admin-clients")
	base := config.Config{AVTLSAddr: ":8443", AdminAddr: ":9443", AdminClientsFile: pins}
	if got := listenerAddrs(base); !slices.Equal(got, []string{":8443"}) {
		t.Errorf("AV only: %v", got)
	}
	// ピンのファイルがあれば（空でも）管理API も待ち受ける
	if err := os.WriteFile(pins, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := listenerAddrs(base); !slices.Equal(got, []string{":8443", ":9443"}) {
		t.Errorf("all listeners: %v", got)
	}
}

func TestCheckListeners(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, open, _ := net.SplitHostPort(ln.Addr().String())

	// 閉じたポートを用意する（一度開いてすぐ閉じる）。
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, closed, _ := net.SplitHostPort(tmp.Addr().String())
	tmp.Close()

	if err := checkListeners(t.Context(), []string{":" + open}); err != nil {
		t.Errorf("open port: %v", err)
	}
	if err := checkListeners(t.Context(), []string{":" + open, ":" + closed}); err == nil {
		t.Error("closed port: want error")
	}
	if err := checkListeners(t.Context(), []string{"no-port"}); err == nil {
		t.Error("bad address: want error")
	}
}
