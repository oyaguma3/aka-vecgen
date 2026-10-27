package main

import (
	"net"
	"slices"
	"testing"

	"github.com/oyaguma3/aka-vecgen/internal/config"
)

func TestListenerAddrs(t *testing.T) {
	base := config.Config{AVTLSAddr: ":8443", AdminAddr: ":9443"}
	if got := listenerAddrs(base); !slices.Equal(got, []string{":8443"}) {
		t.Errorf("AV only: %v", got)
	}
	all := base
	all.AVPlainAddr = ":8080"
	all.AdminClients = map[string]string{"00": "bff"}
	if got := listenerAddrs(all); !slices.Equal(got, []string{":8443", ":8080", ":9443"}) {
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
