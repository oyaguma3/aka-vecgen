package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/config"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

// fakeStore は Server が使うデータ操作をメモリ上で模す。
type fakeStore struct {
	mu      sync.Mutex
	clients map[string]store.Client // フィンガープリント → クライアント
	certs   map[store.CertSlot]store.ServerCertificate
}

func newFakeStore() *fakeStore {
	return &fakeStore{clients: map[string]store.Client{}, certs: map[store.CertSlot]store.ServerCertificate{}}
}

func (f *fakeStore) Allocate(context.Context, store.AllocateRequest) (store.Allocation, error) {
	return store.Allocation{}, store.ErrNotFound
}

func (f *fakeStore) ClientByFingerprint(_ context.Context, fp string) (store.Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[fp]
	if !ok {
		return store.Client{}, store.ErrNotFound
	}
	return c, nil
}

func (f *fakeStore) ServerCertificate(_ context.Context, slot store.CertSlot) (store.ServerCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[slot]
	if !ok {
		return store.ServerCertificate{}, store.ErrNotFound
	}
	return c, nil
}

func (f *fakeStore) InitServerCertificate(_ context.Context, slot store.CertSlot, certPEM, keyPEM []byte, source string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.certs[slot]; ok {
		return false, nil
	}
	f.certs[slot] = store.ServerCertificate{CertPEM: certPEM, KeyPEM: keyPEM, Source: source}
	return true, nil
}

func (f *fakeStore) SetServerCertificate(_ context.Context, slot store.CertSlot, certPEM, keyPEM []byte, source string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs[slot] = store.ServerCertificate{CertPEM: certPEM, KeyPEM: keyPEM, Source: source}
	return nil
}

func (f *fakeStore) setClient(fp string, c *store.Client) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c == nil {
		delete(f.clients, fp)
		return
	}
	f.clients[fp] = *c
}

// clientCert はクライアント証明書を作り、TLS 用の証明書とフィンガープリントを返す。
func clientCert(t *testing.T, validFor time.Duration) (tls.Certificate, string) {
	t.Helper()
	certPEM, keyPEM, err := certs.SelfSigned(certs.SelfSignedOptions{CommonName: "test-client", Client: true, ValidFor: validFor})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, certs.Fingerprint(cert.Leaf)
}

// startMTLS は mTLS リスナーと同じ TLS 設定・クライアント識別でテストサーバーを起動し、その URL を返す。
// ハンドラーは識別したクライアントID を本文に返す。
func startMTLS(t *testing.T, fs *fakeStore) (string, *x509.CertPool) {
	t.Helper()
	return startMTLSWithServer(t, fs, func(*Server) {})
}

// startMTLSWithServer は startMTLS と同じだが、リスナーを開いた後に setup を呼ぶ。
func startMTLSWithServer(t *testing.T, fs *fakeStore, setup func(*Server)) (string, *x509.CertPool) {
	t.Helper()
	cfg := config.Config{AVTLSHosts: []string{"127.0.0.1"}}
	s, err := New(t.Context(), cfg, fs, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, clientIDFromContext(r))
	})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", s.avTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	srv := s.httpServer(s.identifyAVClient(echo))
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	setup(s)

	// 自動生成された自己署名サーバー証明書を、クライアント側で信頼する。
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(fs.certs[store.CertSlotAV].CertPEM) {
		t.Fatal("generated av certificate is not valid PEM")
	}
	return "https://" + ln.Addr().String(), pool
}

// get は cert を提示して（nil なら提示せずに）リクエストを送る。接続は毎回張り直す。
func get(url string, pool *x509.CertPool, cert *tls.Certificate) (int, string, error) {
	tlsCfg := &tls.Config{RootCAs: pool}
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg, DisableKeepAlives: true}}
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

func TestMTLSClientIdentification(t *testing.T) {
	fs := newFakeStore()
	url, pool := startMTLS(t, fs)

	registered, fp := clientCert(t, time.Hour)
	fs.setClient(fp, &store.Client{ID: 42, Enabled: true})

	// 登録済みの証明書は通り、クライアントID が識別される。
	status, body, err := get(url, pool, &registered)
	if err != nil || status != http.StatusOK || body != "42" {
		t.Errorf("registered client: status = %d, body = %q, err = %v", status, body, err)
	}

	// 証明書なしはハンドシェイクで拒否する。
	if _, _, err := get(url, pool, nil); err == nil {
		t.Error("no client certificate: want handshake failure")
	}

	// 未登録の証明書はハンドシェイクで拒否する。
	unknown, _ := clientCert(t, time.Hour)
	if _, _, err := get(url, pool, &unknown); err == nil {
		t.Error("unregistered certificate: want handshake failure")
	}

	// 無効化したクライアントはハンドシェイクで拒否する。
	fs.setClient(fp, &store.Client{ID: 42, Enabled: false})
	if _, _, err := get(url, pool, &registered); err == nil {
		t.Error("disabled client: want handshake failure")
	}

	// 有効期限が切れた証明書は、登録済みでも拒否する。
	expired, expiredFP := clientCert(t, time.Minute) // SelfSigned は NotBefore を 5 分前にするので期限切れになる
	fs.setClient(expiredFP, &store.Client{ID: 43, Enabled: true})
	if _, _, err := get(url, pool, &expired); err == nil {
		t.Error("expired certificate: want handshake failure")
	}
}

// 接続を張ったままクライアントを削除した場合、次のリクエストで弾く。
func TestMTLSClientDeletedAfterHandshake(t *testing.T) {
	fs := newFakeStore()
	url, pool := startMTLS(t, fs)

	cert, fp := clientCert(t, time.Hour)
	fs.setClient(fp, &store.Client{ID: 42, Enabled: true})

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}},
	}}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request: status = %d", resp.StatusCode)
	}

	fs.setClient(fp, nil)
	resp, err = client.Get(url) // 同じ接続を再利用する
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("after delete: status = %d, want 403", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q", ct)
	}
}

// 保存済みのサーバー証明書があれば、それを使い、再生成しない。
func TestAVCertificateIsReused(t *testing.T) {
	fs := newFakeStore()
	cfg := config.Config{AVTLSHosts: []string{"localhost"}}
	log := slog.New(slog.DiscardHandler)

	s1, err := New(t.Context(), cfg, fs, log)
	if err != nil {
		t.Fatal(err)
	}
	if fs.certs[store.CertSlotAV].Source != store.CertSourceSelfSigned {
		t.Errorf("Source = %q", fs.certs[store.CertSlotAV].Source)
	}
	s2, err := New(t.Context(), cfg, fs, log)
	if err != nil {
		t.Fatal(err)
	}
	if certs.Fingerprint(s1.avCert.Load().Leaf) != certs.Fingerprint(s2.avCert.Load().Leaf) {
		t.Error("av certificate was regenerated on the second start")
	}
	leaf := s1.avCert.Load().Leaf
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" {
		t.Errorf("DNSNames = %v", leaf.DNSNames)
	}
}

// 管理API のリスナーは、静的に設定された管理クライアントの証明書だけを受け付ける。
func TestAdminClientIdentification(t *testing.T) {
	configured, fp := clientCert(t, time.Hour)
	expired, expiredFP := clientCert(t, time.Minute) // SelfSigned は NotBefore を 5 分前にするので期限切れになる
	cfg := config.Config{
		AVTLSHosts:    []string{"127.0.0.1"},
		AdminTLSHosts: []string{"127.0.0.1"},
		AdminClients:  map[string]string{fp: "bff", expiredFP: "old-bff"},
	}
	fs := newFakeStore()
	s, err := New(t.Context(), cfg, fs, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if !s.AdminEnabled() {
		t.Fatal("AdminEnabled = false with configured admin clients")
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", s.adminTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	srv := s.httpServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, s.AdminClientName(r))
	}))
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	url := "https://" + ln.Addr().String()

	// 管理API は AV とは別のサーバー証明書を提示する。
	adminPEM, avPEM := fs.certs[store.CertSlotAdmin].CertPEM, fs.certs[store.CertSlotAV].CertPEM
	if len(adminPEM) == 0 || string(adminPEM) == string(avPEM) {
		t.Fatal("admin listener does not have its own server certificate")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(adminPEM)

	status, body, err := get(url, pool, &configured)
	if err != nil || status != http.StatusOK || body != "bff" {
		t.Errorf("configured client: status = %d, body = %q, err = %v", status, body, err)
	}
	if _, _, err := get(url, pool, nil); err == nil {
		t.Error("no client certificate: want handshake failure")
	}
	other, _ := clientCert(t, time.Hour)
	if _, _, err := get(url, pool, &other); err == nil {
		t.Error("unconfigured certificate: want handshake failure")
	}
	if _, _, err := get(url, pool, &expired); err == nil {
		t.Error("expired certificate: want handshake failure")
	}

	// AV クライアントとして登録されていても、管理API には入れない。
	avClient, avFP := clientCert(t, time.Hour)
	fs.setClient(avFP, &store.Client{ID: 1, Enabled: true})
	if _, _, err := get(url, pool, &avClient); err == nil {
		t.Error("AV client certificate on the admin listener: want handshake failure")
	}
}

// 管理クライアントが設定されていなければ、管理API を起動せず、証明書も作らない。
func TestAdminDisabledWithoutClients(t *testing.T) {
	fs := newFakeStore()
	s, err := New(t.Context(), config.Config{AVTLSHosts: []string{"localhost"}}, fs, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if s.AdminEnabled() {
		t.Error("AdminEnabled = true without admin clients")
	}
	if _, ok := fs.certs[store.CertSlotAdmin]; ok {
		t.Error("admin certificate was generated although the admin api is disabled")
	}
}

// AV 用サーバー証明書の差し替えは、動作中のリスナーの新しい接続に反映される。
func TestAVCertificateHotSwap(t *testing.T) {
	fs := newFakeStore()
	url, _ := startMTLSWithServer(t, fs, func(s *Server) {
		certPEM, keyPEM, err := certs.SelfSigned(certs.SelfSignedOptions{CommonName: "swapped", Hosts: []string{"127.0.0.1"}, ValidFor: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		sc, err := s.ReplaceAVCertificate(t.Context(), certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		if sc.Source != store.CertSourceUploaded {
			t.Errorf("Source = %q", sc.Source)
		}
		// 秘密鍵が証明書と対応していなければ差し替えない。
		_, otherKey, _ := certs.SelfSigned(certs.SelfSignedOptions{CommonName: "x", ValidFor: time.Hour})
		if _, err := s.ReplaceAVCertificate(t.Context(), certPEM, otherKey); !errors.Is(err, certs.ErrInvalid) {
			t.Errorf("mismatched key: err = %v, want certs.ErrInvalid", err)
		}
	})

	cert, fp := clientCert(t, time.Hour)
	fs.setClient(fp, &store.Client{ID: 1, Enabled: true})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(fs.certs[store.CertSlotAV].CertPEM)
	conn, err := tls.Dial("tcp", strings.TrimPrefix(url, "https://"), &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if cn := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "swapped" {
		t.Errorf("listener presents CN=%q, want swapped", cn)
	}
}
