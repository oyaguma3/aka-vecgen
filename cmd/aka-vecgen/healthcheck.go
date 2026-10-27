package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/config"
)

// healthcheckTimeout は、healthcheck でリスナー 1 つに接続するときの上限。
const healthcheckTimeout = 3 * time.Second

// healthcheckCommand は、同じコンテナで動いているサーバーのリスナーが接続を受け付けているかを確かめる。
// distroless のイメージには curl がないので、compose の healthcheck はこれを使う。
// 認証ベクターAPI と管理API は mTLS でクライアント証明書がないと要求を送れないので、TCP で接続できるかだけを見る
// （Valkey の状態などは、ログと管理API の /status で確かめる）。
func healthcheckCommand(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	return checkListeners(ctx, listenerAddrs(cfg))
}

// listenerAddrs は、設定から有効なリスナーの待ち受けアドレスを返す。
func listenerAddrs(cfg config.Config) []string {
	addrs := []string{cfg.AVTLSAddr}
	if len(cfg.AdminClients) > 0 {
		addrs = append(addrs, cfg.AdminAddr)
	}
	return addrs
}

// checkListeners は、各待ち受けアドレスのポートに、ループバックで TCP 接続できるかを確かめる。
func checkListeners(ctx context.Context, addrs []string) error {
	var d net.Dialer
	for _, addr := range addrs {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("listen address %q: %w", addr, err)
		}
		dctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
		conn, err := d.DialContext(dctx, "tcp", net.JoinHostPort("127.0.0.1", port))
		cancel()
		if err != nil {
			return fmt.Errorf("listener %s: %w", addr, err)
		}
		conn.Close()
	}
	return nil
}
