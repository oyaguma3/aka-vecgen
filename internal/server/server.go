// Package server は認証ベクターAPI と管理API のリスナーを組み立てて起動する。
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
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

	// avCert は AV の mTLS リスナーが提示するサーバー証明書。SIGHUP で読み直す（Reload）。
	avCert atomic.Pointer[tls.Certificate]
	// adminCert は管理API のリスナーが提示するサーバー証明書。SIGHUP で読み直す。
	adminCert atomic.Pointer[tls.Certificate]
	// adminEnabled は管理API を起動するか（起動のときにピンのファイルがあったか）。
	adminEnabled bool
	// admin は管理クライアントのピンと、読み込んだ日時。SIGHUP で読み直す。
	admin atomic.Pointer[adminClients]
}

type adminClients struct {
	clients  config.AdminClients
	loadedAt time.Time
}

// New はサーバーを作る。サーバー証明書がまだなければ自己署名を生成して保存する。
// 管理クライアントのピンのファイル（cfg.AdminClientsFile）がなければ管理API を起動しない。
// ファイルがあって形が違えば起動しない（設計概要 §10.1、確認事項 E2）。
func New(ctx context.Context, cfg config.Config, st Store, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, store: st, log: log}

	cert, err := s.loadCertificate(ctx, store.CertSlotAV, cfg.AVTLSHosts)
	if err != nil {
		return nil, err
	}
	s.avCert.Store(cert)

	clients, err := config.LoadAdminClients(cfg.AdminClientsFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
		log.Info("admin api is disabled: the admin clients file does not exist", "event_id", "ADMIN_API_DISABLED", "file", cfg.AdminClientsFile)
	case err != nil:
		return nil, fmt.Errorf("admin clients: %w", err)
	default:
		s.adminEnabled = true
		s.admin.Store(&adminClients{clients: clients, loadedAt: time.Now().UTC()})
		log.Info("loaded admin clients", "event_id", "ADMIN_CLIENTS_LOADED", "names", clients.Names(), "count", len(clients))
		adminCert, err := s.loadCertificate(ctx, store.CertSlotAdmin, cfg.AdminTLSHosts)
		if err != nil {
			return nil, err
		}
		s.adminCert.Store(adminCert)
	}
	return s, nil
}

// AdminEnabled は管理API を起動するかを返す。
func (s *Server) AdminEnabled() bool { return s.adminEnabled }

// AdminClients は管理クライアントの識別名と、ピンを読み込んだ日時を返す（管理API の /status 用）。
func (s *Server) AdminClients() (names []string, loadedAt time.Time) {
	a := s.admin.Load()
	if a == nil {
		return nil, time.Time{}
	}
	return a.clients.Names(), a.loadedAt
}

// CertificateNotAfter は、提示しているサーバー証明書の期限を返す（管理API を起動していなければ管理用は零値）。
func (s *Server) CertificateNotAfter() (av, admin time.Time) {
	if c := s.avCert.Load(); c != nil {
		av = c.Leaf.NotAfter
	}
	if c := s.adminCert.Load(); c != nil {
		admin = c.Leaf.NotAfter
	}
	return av, admin
}

// ReloadResult は Reload の結果。
type ReloadResult struct {
	// AdminClients は読み直した管理クライアントの識別名（管理API を起動していない、または失敗なら nil）。
	AdminClients []string
	// AVCertChanged・AdminCertChanged は、提示するサーバー証明書が変わったか。
	AVCertChanged, AdminCertChanged bool
}

// Reload は、管理クライアントのピンのファイルと、AV 用・管理用のサーバー証明書（Valkey）を読み直す（SIGHUP。確認事項 E1）。
// 読めない・形が違うものは前のまま続け、エラーをまとめて返す。
// AV クライアントの変更は、ハンドシェイクと要求ごとに Valkey を見るので、読み直しは要らない。
func (s *Server) Reload(ctx context.Context) (ReloadResult, error) {
	var res ReloadResult
	var errs []error
	if s.adminEnabled {
		clients, err := config.LoadAdminClients(s.cfg.AdminClientsFile)
		if err != nil {
			s.log.Error("failed to reload admin clients (keeping the previous ones)", "event_id", "ADMIN_CLIENTS_RELOAD_ERR", "error", err)
			errs = append(errs, err)
		} else {
			s.admin.Store(&adminClients{clients: clients, loadedAt: time.Now().UTC()})
			res.AdminClients = clients.Names()
			s.log.Info("reloaded admin clients", "event_id", "ADMIN_CLIENTS_RELOADED", "names", res.AdminClients, "count", len(clients))
		}
	}
	var err error
	if res.AVCertChanged, err = s.reloadCertificate(ctx, store.CertSlotAV, &s.avCert); err != nil {
		errs = append(errs, err)
	}
	if s.adminEnabled {
		if res.AdminCertChanged, err = s.reloadCertificate(ctx, store.CertSlotAdmin, &s.adminCert); err != nil {
			errs = append(errs, err)
		}
	}
	return res, errors.Join(errs...)
}

// reloadCertificate は Valkey のサーバー証明書を読み直して差し替える。変わったかを返す。
func (s *Server) reloadCertificate(ctx context.Context, slot store.CertSlot, cur *atomic.Pointer[tls.Certificate]) (bool, error) {
	sc, err := s.store.ServerCertificate(ctx, slot)
	if err == nil {
		var cert tls.Certificate
		if cert, err = tls.X509KeyPair(sc.CertPEM, sc.KeyPEM); err == nil {
			old := cur.Load()
			changed := old == nil || !bytes.Equal(old.Certificate[0], cert.Certificate[0])
			cur.Store(&cert)
			s.log.Info("reloaded server certificate", "event_id", "SERVER_CERT_RELOADED", "slot", string(slot), "changed", changed,
				"source", sc.Source, "fingerprint", certs.Fingerprint(cert.Leaf), "not_after", cert.Leaf.NotAfter)
			return changed, nil
		}
	}
	s.log.Error("failed to reload server certificate (keeping the previous one)", "event_id", "SERVER_CERT_RELOAD_ERR", "slot", string(slot), "error", err)
	return false, fmt.Errorf("server certificate %s: %w", slot, err)
}

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
			s.log.Info("generated self-signed server certificate", "event_id", "SERVER_CERT_GENERATED", "slot", string(slot), "hosts", hosts)
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
	s.log.Info("loaded server certificate", "event_id", "SERVER_CERT_LOADED", "slot", string(slot),
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

// ---- AV 用サーバー証明書（管理API の読み出しの口から使う） ----

// AVCertificate は現在の AV 用サーバー証明書を返す。
func (s *Server) AVCertificate(ctx context.Context) (store.ServerCertificate, error) {
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
		s.log.Warn("client certificate rejected", "event_id", "AV_CLIENT_REJECTED", "reason", "outside validity period", "fingerprint", fp)
		return errors.New("client certificate is outside its validity period")
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	c, err := s.store.ClientByFingerprint(ctx, fp)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.log.Warn("client certificate rejected", "event_id", "AV_CLIENT_REJECTED", "reason", "not registered", "fingerprint", fp)
		return errors.New("client certificate is not registered")
	case err != nil:
		s.log.Error("client lookup failed", "event_id", "AV_CLIENT_LOOKUP_ERR", "error", err)
		return errors.New("client lookup failed")
	case !c.Enabled:
		s.log.Warn("client certificate rejected", "event_id", "AV_CLIENT_REJECTED", "reason", "client disabled", "client_id", c.ID)
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
			s.log.Warn("av request rejected", "event_id", "AV_REJECTED", "listener", "av-mtls", "reason", avapi.ReasonClientUnknown, "remote", r.RemoteAddr)
			avapi.WriteRejected(w)
			return
		}
		c, err := s.store.ClientByFingerprint(r.Context(), certs.Fingerprint(r.TLS.PeerCertificates[0]))
		switch {
		case errors.Is(err, store.ErrNotFound):
			// ハンドシェイクの後に削除されたクライアント。一般的な拒否にする（契約 §9.2）。
			s.log.Warn("av request rejected", "event_id", "AV_REJECTED", "listener", "av-mtls", "reason", avapi.ReasonClientUnknown, "remote", r.RemoteAddr)
			avapi.WriteRejected(w)
			return
		case err != nil:
			s.log.Error("client lookup failed", "event_id", "AV_CLIENT_LOOKUP_ERR", "error", err)
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
// クライアント証明書は、ピンのファイルの管理クライアントのフィンガープリントと照合する（SIGHUP で読み直す）。
func (s *Server) adminTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAnyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.adminCert.Load(), nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("client certificate required")
			}
			cert := cs.PeerCertificates[0]
			fp := certs.Fingerprint(cert)
			if _, ok := s.admin.Load().clients[fp]; !ok {
				s.log.Warn("admin client certificate rejected", "event_id", "ADMIN_CLIENT_REJECTED", "reason", "not configured", "fingerprint", fp)
				return errors.New("client certificate is not a configured admin client")
			}
			if err := certs.CheckValidity(cert); err != nil {
				s.log.Warn("admin client certificate rejected", "event_id", "ADMIN_CLIENT_REJECTED", "reason", "outside validity period", "fingerprint", fp)
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
	a := s.admin.Load()
	if a == nil {
		return ""
	}
	return a.clients[certs.Fingerprint(r.TLS.PeerCertificates[0])]
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

	// 管理API
	if s.AdminEnabled() {
		ln, err := tls.Listen("tcp", s.cfg.AdminAddr, s.adminTLSConfig())
		if err != nil {
			return listeners, fmt.Errorf("listen admin %s: %w", s.cfg.AdminAddr, err)
		}
		listeners = append(listeners, listener{"admin", s.httpServer(admin), ln})
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
		s.log.Info("listening", "event_id", "LISTENING", "listener", l.name, "addr", l.ln.Addr().String())
		wg.Go(func() {
			if err := l.srv.Serve(l.ln); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", l.name, err)
			}
		})
	}

	var runErr error
	select {
	case <-ctx.Done():
		s.log.Info("shutting down", "event_id", "SHUTDOWN")
	case runErr = <-errc:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, l := range listeners {
		if err := l.srv.Shutdown(shutdownCtx); err != nil {
			s.log.Warn("shutdown", "event_id", "SHUTDOWN_ERR", "listener", l.name, "error", err)
		}
	}
	wg.Wait()
	return runErr
}
