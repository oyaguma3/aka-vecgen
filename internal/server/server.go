// Package server は認証ベクターAPI と管理API のリスナーを組み立てて起動する。
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/avapi"
	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/config"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

const (
	// lookupTimeout は TLS ハンドシェイク中にクライアント証明書を照合するときの上限時間。
	lookupTimeout = 3 * time.Second
	// selfSignedValidFor は自動生成する自己署名サーバー証明書の有効期間。
	selfSignedValidFor = 10 * 365 * 24 * time.Hour
	shutdownTimeout    = 10 * time.Second
)

// Store はサーバーが使うデータ操作。
type Store interface {
	avapi.Allocator
	ClientByFingerprint(ctx context.Context, fp string) (store.Client, error)
	ServerCertificate(ctx context.Context, slot store.CertSlot) (store.ServerCertificate, error)
	InitServerCertificate(ctx context.Context, slot store.CertSlot, certPEM, keyPEM []byte, source string) (bool, error)
	SetServerCertificate(ctx context.Context, slot store.CertSlot, certPEM, keyPEM []byte, source string) error
}

// Server は認証ベクターAPI と管理API のリスナー群。
type Server struct {
	cfg   config.Config
	store Store
	log   *slog.Logger

	// avCert は AV の mTLS リスナーが提示するサーバー証明書。再起動なしで差し替えられる。
	avCert atomic.Pointer[tls.Certificate]
	// adminCert は管理API のリスナーが提示するサーバー証明書。
	adminCert *tls.Certificate
}

// New はサーバーを作る。サーバー証明書がまだなければ自己署名を生成して保存する。
func New(ctx context.Context, cfg config.Config, st Store, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, store: st, log: log}

	cert, err := s.loadCertificate(ctx, store.CertSlotAV, cfg.AVTLSHosts)
	if err != nil {
		return nil, err
	}
	s.avCert.Store(cert)

	if s.AdminEnabled() {
		if s.adminCert, err = s.loadCertificate(ctx, store.CertSlotAdmin, cfg.AdminTLSHosts); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// AdminEnabled は管理API を起動するかを返す。管理クライアントが 1 つも設定されていなければ起動しない。
func (s *Server) AdminEnabled() bool { return len(s.cfg.AdminClients) > 0 }

// loadCertificate は保存済みのサーバー証明書を読む。なければ自己署名を生成して保存する。
func (s *Server) loadCertificate(ctx context.Context, slot store.CertSlot, hosts []string) (*tls.Certificate, error) {
	sc, err := s.store.ServerCertificate(ctx, slot)
	if errors.Is(err, store.ErrNotFound) {
		certPEM, keyPEM, err := selfSigned(hosts)
		if err != nil {
			return nil, err
		}
		created, err := s.store.InitServerCertificate(ctx, slot, certPEM, keyPEM, store.CertSourceSelfSigned)
		if err != nil {
			return nil, err
		}
		if created {
			s.log.Info("generated self-signed server certificate", "slot", string(slot), "hosts", hosts)
		}
		// 他のプロセスが先に保存していた場合に備えて、保存済みのものを読み直す。
		sc, err = s.store.ServerCertificate(ctx, slot)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(sc.CertPEM, sc.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("stored server certificate %s is invalid: %w", slot, err)
	}
	s.log.Info("loaded server certificate", "slot", string(slot),
		"source", sc.Source, "fingerprint", certs.Fingerprint(cert.Leaf), "not_after", cert.Leaf.NotAfter)
	return &cert, nil
}

func selfSigned(hosts []string) (certPEM, keyPEM []byte, err error) {
	certPEM, keyPEM, err = certs.SelfSigned(certs.SelfSignedOptions{
		CommonName: "aka-vecgen",
		Hosts:      hosts,
		ValidFor:   selfSignedValidFor,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("generate self-signed server certificate: %w", err)
	}
	return certPEM, keyPEM, nil
}

// ---- AV 用サーバー証明書の管理（管理API から使う） ----

// AVCertificate は現在の AV 用サーバー証明書を返す。
func (s *Server) AVCertificate(ctx context.Context) (store.ServerCertificate, error) {
	return s.store.ServerCertificate(ctx, store.CertSlotAV)
}

// ReplaceAVCertificate は AV 用サーバー証明書を持ち込みのものに差し替える。
// 以後の新しい接続から反映される。内容が不正なら certs.ErrInvalid を返す。
func (s *Server) ReplaceAVCertificate(ctx context.Context, certPEM, keyPEM []byte) (store.ServerCertificate, error) {
	return s.setAVCertificate(ctx, certPEM, keyPEM, store.CertSourceUploaded)
}

// ResetAVCertificate は自己署名証明書を再生成し、AV 用サーバー証明書を置き換える。
func (s *Server) ResetAVCertificate(ctx context.Context) (store.ServerCertificate, error) {
	certPEM, keyPEM, err := selfSigned(s.cfg.AVTLSHosts)
	if err != nil {
		return store.ServerCertificate{}, err
	}
	return s.setAVCertificate(ctx, certPEM, keyPEM, store.CertSourceSelfSigned)
}

func (s *Server) setAVCertificate(ctx context.Context, certPEM, keyPEM []byte, source string) (store.ServerCertificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return store.ServerCertificate{}, fmt.Errorf("%w: %v", certs.ErrInvalid, err)
	}
	if err := certs.CheckValidity(cert.Leaf); err != nil {
		return store.ServerCertificate{}, err
	}
	if err := s.store.SetServerCertificate(ctx, store.CertSlotAV, certPEM, keyPEM, source); err != nil {
		return store.ServerCertificate{}, err
	}
	s.avCert.Store(&cert)
	s.log.Info("replaced av server certificate",
		"source", source, "fingerprint", certs.Fingerprint(cert.Leaf), "not_after", cert.Leaf.NotAfter)
	return s.store.ServerCertificate(ctx, store.CertSlotAV)
}

// ---- AV の mTLS リスナー ----

// avTLSConfig は AV の mTLS リスナーの TLS 設定を返す。
// クライアント証明書は CA では検証せず、登録済みのフィンガープリントと照合する。
func (s *Server) avTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAnyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.avCert.Load(), nil
		},
		// セッション再開時にも呼ばれるので、無効化・削除されたクライアントは再接続できない。
		VerifyConnection: s.verifyAVClient,
	}
}

func (s *Server) verifyAVClient(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("client certificate required")
	}
	cert := cs.PeerCertificates[0]
	fp := certs.Fingerprint(cert)

	if err := certs.CheckValidity(cert); err != nil {
		s.log.Warn("client certificate rejected", "reason", "outside validity period", "fingerprint", fp)
		return errors.New("client certificate is outside its validity period")
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	c, err := s.store.ClientByFingerprint(ctx, fp)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.log.Warn("client certificate rejected", "reason", "not registered", "fingerprint", fp)
		return errors.New("client certificate is not registered")
	case err != nil:
		s.log.Error("client lookup failed", "error", err)
		return errors.New("client lookup failed")
	case !c.Enabled:
		s.log.Warn("client certificate rejected", "reason", "client disabled", "client_id", c.ID)
		return errors.New("client is disabled")
	}
	return nil
}

type clientIDKey struct{}

// identifyAVClient は、提示されたクライアント証明書からクライアントID を引いてコンテキストに入れる。
// ハンドシェイク後に削除されたクライアントは、ここで弾く。
// 無効化と加入者ごとの許可は、払い出しスクリプトがリクエストごとに確認する。
func (s *Server) identifyAVClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			avapi.WriteForbidden(w, "client certificate required")
			return
		}
		c, err := s.store.ClientByFingerprint(r.Context(), certs.Fingerprint(r.TLS.PeerCertificates[0]))
		switch {
		case errors.Is(err, store.ErrNotFound):
			avapi.WriteForbidden(w, "client certificate is not registered")
			return
		case err != nil:
			s.log.Error("client lookup failed", "error", err)
			avapi.WriteInternalError(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIDKey{}, c.ID)))
	})
}

func clientIDFromContext(r *http.Request) int64 {
	id, _ := r.Context().Value(clientIDKey{}).(int64)
	return id
}

// ---- 管理API のリスナー ----

// adminTLSConfig は管理API のリスナーの TLS 設定を返す。
// クライアント証明書は、静的に設定された管理クライアントのフィンガープリントと照合する。
func (s *Server) adminTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{*s.adminCert},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("client certificate required")
			}
			cert := cs.PeerCertificates[0]
			fp := certs.Fingerprint(cert)
			if _, ok := s.cfg.AdminClients[fp]; !ok {
				s.log.Warn("admin client certificate rejected", "reason", "not configured", "fingerprint", fp)
				return errors.New("client certificate is not a configured admin client")
			}
			if err := certs.CheckValidity(cert); err != nil {
				s.log.Warn("admin client certificate rejected", "reason", "outside validity period", "fingerprint", fp)
				return errors.New("client certificate is outside its validity period")
			}
			return nil
		},
	}
}

// AdminClientName は、管理API のリクエストを送ってきた管理クライアントの識別名を返す。
func (s *Server) AdminClientName(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return s.cfg.AdminClients[certs.Fingerprint(r.TLS.PeerCertificates[0])]
}

// ---- 起動 ----

func (s *Server) httpServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          newHTTPErrorLog(s.log.Handler()),
	}
}

type listener struct {
	name string
	srv  *http.Server
	ln   net.Listener
}

// listen は有効なリスナーをすべて開く。途中で失敗したら、開いたものを閉じて返す。
// admin は管理API のハンドラーで、AdminEnabled が false なら使わない。
func (s *Server) listen(admin http.Handler) (listeners []listener, err error) {
	defer func() {
		if err != nil {
			for _, l := range listeners {
				l.ln.Close()
			}
		}
	}()

	// AV / mTLS
	mtls := &avapi.Handler{Allocator: s.store, Log: s.log.With("listener", "av-mtls"), ClientID: clientIDFromContext}
	ln, err := tls.Listen("tcp", s.cfg.AVTLSAddr, s.avTLSConfig())
	if err != nil {
		return nil, fmt.Errorf("listen av-mtls %s: %w", s.cfg.AVTLSAddr, err)
	}
	listeners = append(listeners, listener{"av-mtls", s.httpServer(s.identifyAVClient(mtls.Routes())), ln})

	// AV / 平文HTTP（既定で無効）
	if s.cfg.AVPlainAddr != "" {
		plain := &avapi.Handler{
			Allocator: s.store,
			Log:       s.log.With("listener", "av-plain"),
			ClientID:  func(*http.Request) int64 { return 0 },
		}
		ln, err := net.Listen("tcp", s.cfg.AVPlainAddr)
		if err != nil {
			return listeners, fmt.Errorf("listen av-plain %s: %w", s.cfg.AVPlainAddr, err)
		}
		listeners = append(listeners, listener{"av-plain", s.httpServer(plain.Routes()), ln})
	}

	// 管理API
	if s.AdminEnabled() {
		ln, err := tls.Listen("tcp", s.cfg.AdminAddr, s.adminTLSConfig())
		if err != nil {
			return listeners, fmt.Errorf("listen admin %s: %w", s.cfg.AdminAddr, err)
		}
		listeners = append(listeners, listener{"admin", s.httpServer(admin), ln})
	} else {
		s.log.Info("admin api is disabled: no admin clients are configured")
	}
	return listeners, nil
}

// Run はリスナーを起動し、ctx が終了するかいずれかのリスナーが失敗するまで待つ。
// admin は管理API のハンドラー。
func (s *Server) Run(ctx context.Context, admin http.Handler) error {
	listeners, err := s.listen(admin)
	if err != nil {
		return err
	}

	errc := make(chan error, len(listeners))
	var wg sync.WaitGroup
	for _, l := range listeners {
		s.log.Info("listening", "listener", l.name, "addr", l.ln.Addr().String())
		wg.Go(func() {
			if err := l.srv.Serve(l.ln); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", l.name, err)
			}
		})
	}

	var runErr error
	select {
	case <-ctx.Done():
		s.log.Info("shutting down")
	case runErr = <-errc:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, l := range listeners {
		if err := l.srv.Shutdown(shutdownCtx); err != nil {
			s.log.Warn("shutdown", "listener", l.name, "error", err)
		}
	}
	wg.Wait()
	return runErr
}
