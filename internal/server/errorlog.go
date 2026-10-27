package server

import (
	"context"
	"log"
	"log/slog"
	"regexp"
	"strings"
)

// loopbackHandshakeEOF は、ループバックからの接続が TLS のハンドシェイクの前に切れたときの http.Server のエラーの文。
// compose の healthcheck（aka-vecgen healthcheck）は、コンテナの中のループバックから TCP で接続してすぐ切るので、
// 確かめるたびにこの文が出る。
var loopbackHandshakeEOF = regexp.MustCompile(`^http: TLS handshake error from (127\.0\.0\.1|\[::1\]):\d+: EOF$`)

// newHTTPErrorLog は http.Server の ErrorLog を作る。エラーは WARN で slog に流すが、ループバックからの
// ハンドシェイクの前の切断（healthcheck）だけは DEBUG にする（WARN だとログが healthcheck で埋まる）。
// 外からの接続は compose のネットワークや公開したポートから別のアドレスで届くので、WARN のまま残る。
// event_id は、TLS のハンドシェイクの失敗なら TLS_HANDSHAKE_ERR、ほかは HTTP_SERVER_ERR にする（設計概要 §13.1）。
func newHTTPErrorLog(h slog.Handler) *log.Logger {
	return log.New(httpErrorWriter{log: slog.New(h)}, "", 0)
}

type httpErrorWriter struct{ log *slog.Logger }

func (w httpErrorWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSuffix(string(p), "\n")
	level := slog.LevelWarn
	if loopbackHandshakeEOF.MatchString(msg) {
		level = slog.LevelDebug
	}
	eventID := "HTTP_SERVER_ERR"
	if strings.HasPrefix(msg, "http: TLS handshake error") {
		eventID = "TLS_HANDSHAKE_ERR"
	}
	w.log.Log(context.Background(), level, msg, "event_id", eventID)
	return len(p), nil
}
