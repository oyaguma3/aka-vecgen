package store

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/aka"
	"github.com/oyaguma3/aka-vecgen/internal/certs"
)

// 結合テストは実際の Valkey に接続する。接続先を環境変数で指定したときだけ実行する。
//
//	VECGEN_TEST_VALKEY_ADDR=127.0.0.1:16379 VECGEN_TEST_VALKEY_PASSWORD=... go test ./internal/store/
//
// テストは論理データベース 1 番の全データを消すので、専用の Valkey を使うこと。
func openTestStore(t *testing.T) *Store {
	t.Helper()
	addr := os.Getenv("VECGEN_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("VECGEN_TEST_VALKEY_ADDR is not set")
	}
	s, err := Open(t.Context(), Options{Addr: addr, Password: os.Getenv("VECGEN_TEST_VALKEY_PASSWORD"), DB: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.c.Do(t.Context(), s.c.B().Flushdb().Build()).Error(); err != nil {
		t.Fatal(err)
	}
	return s
}

func testSubscriber(imsi string, typ aka.SQNType) Subscriber {
	return Subscriber{
		IMSI:    imsi,
		Ki:      []byte("0123456789abcdef"),
		OPc:     []byte("fedcba9876543210"),
		AMF:     0x8000,
		SQNType: typ,
	}
}

func testCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	certPEM, _, err := certs.SelfSigned(certs.SelfSignedOptions{CommonName: name, Client: true, ValidFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := certs.ParsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func addClient(t *testing.T, s *Store, name, networkName string) Client {
	t.Helper()
	c, err := s.CreateClient(t.Context(), NewClient{Name: name, Cert: testCert(t, name), Enabled: true, NetworkName: networkName})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSubscriberLifecycle(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	c1 := addClient(t, s, "c1", "")
	c2 := addClient(t, s, "c2", "")

	sub := testSubscriber("440100000000001", aka.SQNInc32)
	sub.SQN = 0x20
	sub.AllowPlain = true
	sub.AllowedClientIDs = []int64{c2.ID, c1.ID}
	if err := s.CreateSubscriber(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSubscriber(ctx, sub); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate create: err = %v, want ErrExists", err)
	}

	got, err := s.GetSubscriber(ctx, sub.IMSI)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Ki) != string(sub.Ki) || string(got.OPc) != string(sub.OPc) || got.SQN != 0x20 ||
		got.AMF != 0x8000 || got.SQNType != aka.SQNInc32 || !got.AllowPlain {
		t.Errorf("GetSubscriber = %+v", got)
	}
	if want := []int64{c1.ID, c2.ID}; !slices.Equal(got.AllowedClientIDs, want) {
		t.Errorf("AllowedClientIDs = %v, want %v", got.AllowedClientIDs, want)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}

	// 存在しないクライアントID は登録できない。
	bad := testSubscriber("440100000000002", aka.SQNInc32)
	bad.AllowedClientIDs = []int64{c1.ID, 9999}
	if err := s.CreateSubscriber(ctx, bad); !errors.Is(err, ErrUnknownClient) {
		t.Errorf("unknown client: err = %v, want ErrUnknownClient", err)
	}

	if err := s.DeleteSubscriber(ctx, sub.IMSI); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSubscriber(ctx, sub.IMSI); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: err = %v, want ErrNotFound", err)
	}
	if err := s.DeleteSubscriber(ctx, sub.IMSI); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice: err = %v, want ErrNotFound", err)
	}
}

// Valkey 側のスクリプトと Go 側の SQNType.Sequence が同じ計算をしていることを確認する。
func TestAllocateAdvancesSQN(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	for i, typ := range []aka.SQNType{aka.SQNInc1, aka.SQNInc32, aka.SQNInc33} {
		imsi := fmt.Sprintf("44010000000001%d", i)
		sub := testSubscriber(imsi, typ)
		sub.SQN = 30 // inc33 で IND が 31 から 0 に回る箇所を通る
		sub.AllowPlain = true
		if err := s.CreateSubscriber(ctx, sub); err != nil {
			t.Fatal(err)
		}

		base := sub.SQN
		for _, n := range []int{1, 5, 2, 1, 3} {
			a, err := s.Allocate(ctx, AllocateRequest{IMSI: imsi, N: n, DefaultNetworkName: "WLAN"})
			if err != nil {
				t.Fatalf("%s: %v", typ, err)
			}
			if a.Base != base {
				t.Fatalf("%s: Base = %d, want %d", typ, a.Base, base)
			}
			if a.SQNType != typ || a.Credentials.AMF != 0x8000 || string(a.Credentials.Ki) != string(sub.Ki) {
				t.Fatalf("%s: Allocation = %+v", typ, a)
			}
			sqns, err := typ.Sequence(a.Base, n)
			if err != nil {
				t.Fatal(err)
			}
			base = sqns[len(sqns)-1]

			got, err := s.GetSubscriber(ctx, imsi)
			if err != nil {
				t.Fatal(err)
			}
			if got.SQN != base {
				t.Fatalf("%s: stored SQN after n=%d is %d, want %d", typ, n, got.SQN, base)
			}
		}
	}
}

func TestAllocateWrapsAt48Bits(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	sub := testSubscriber("440100000000020", aka.SQNInc32)
	sub.SQN = aka.SQNMask - 31
	sub.AllowPlain = true
	if err := s.CreateSubscriber(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Allocate(ctx, AllocateRequest{IMSI: sub.IMSI, N: 1}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSubscriber(ctx, sub.IMSI)
	if err != nil {
		t.Fatal(err)
	}
	if got.SQN != 0 {
		t.Errorf("SQN = %d, want 0", got.SQN)
	}
}

func TestAllocateProbeAndResync(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	sub := testSubscriber("440100000000030", aka.SQNInc32)
	sub.SQN = 64
	sub.AllowPlain = true
	if err := s.CreateSubscriber(ctx, sub); err != nil {
		t.Fatal(err)
	}

	// N=0 は SQN を進めない。
	a, err := s.Allocate(ctx, AllocateRequest{IMSI: sub.IMSI, N: 0})
	if err != nil {
		t.Fatal(err)
	}
	if a.Base != 64 {
		t.Errorf("probe Base = %d, want 64", a.Base)
	}
	if got, _ := s.GetSubscriber(ctx, sub.IMSI); got.SQN != 64 {
		t.Errorf("SQN after probe = %d, want 64", got.SQN)
	}

	// 再同期では SQN を置き換えてから進める。
	a, err = s.Allocate(ctx, AllocateRequest{IMSI: sub.IMSI, N: 2, ResyncSQN: new(uint64(3200))})
	if err != nil {
		t.Fatal(err)
	}
	if a.Base != 3200 {
		t.Errorf("resync Base = %d, want 3200", a.Base)
	}
	if got, _ := s.GetSubscriber(ctx, sub.IMSI); got.SQN != 3200+64 {
		t.Errorf("SQN after resync = %d, want %d", got.SQN, 3200+64)
	}
}

func TestAllocateAuthorization(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	allowed := addClient(t, s, "allowed", "")
	other := addClient(t, s, "other", "")

	sub := testSubscriber("440100000000040", aka.SQNInc32)
	sub.AllowedClientIDs = []int64{allowed.ID}
	if err := s.CreateSubscriber(ctx, sub); err != nil {
		t.Fatal(err)
	}
	plainOnly := testSubscriber("440100000000041", aka.SQNInc32)
	plainOnly.AllowPlain = true
	if err := s.CreateSubscriber(ctx, plainOnly); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		imsi     string
		clientID int64
		want     error
	}{
		{"allowed client", sub.IMSI, allowed.ID, nil},
		{"client not in the set", sub.IMSI, other.ID, ErrForbidden},
		{"plain HTTP without the flag", sub.IMSI, 0, ErrForbidden},
		{"plain HTTP with the flag", plainOnly.IMSI, 0, nil},
		// 平文HTTP の許可は、証明書で識別されたクライアントには適用しない。
		{"client on a plain-only subscriber", plainOnly.IMSI, allowed.ID, ErrForbidden},
		{"unknown client id", sub.IMSI, 9999, ErrForbidden},
		{"unknown subscriber", "440100000000099", allowed.ID, ErrNotFound},
	}
	for _, tt := range tests {
		_, err := s.Allocate(ctx, AllocateRequest{IMSI: tt.imsi, ClientID: tt.clientID, N: 1})
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}

	// 拒否された要求は SQN を進めない。
	if got, _ := s.GetSubscriber(ctx, sub.IMSI); got.SQN != 32 {
		t.Errorf("SQN = %d, want 32 (one successful allocation)", got.SQN)
	}

	// 削除したクライアントは、許可集合に ID が残っていても拒否する。
	if err := s.DeleteClient(ctx, allowed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Allocate(ctx, AllocateRequest{IMSI: sub.IMSI, ClientID: allowed.ID, N: 1}); !errors.Is(err, ErrForbidden) {
		t.Errorf("deleted client: err = %v, want ErrForbidden", err)
	}
}

func TestAllocateNetworkName(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	def := addClient(t, s, "default-name", "")
	custom := addClient(t, s, "custom-name", "ETHERNET")

	sub := testSubscriber("440100000000050", aka.SQNInc32)
	sub.AllowPlain = true
	sub.AllowedClientIDs = []int64{def.ID, custom.ID}
	if err := s.CreateSubscriber(ctx, sub); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		clientID  int64
		requested string
		want      string
		wantErr   error
	}{
		{"default, not requested", def.ID, "", "WLAN", nil},
		{"default, matching", def.ID, "WLAN", "WLAN", nil},
		{"default, mismatch", def.ID, "ETHERNET", "", ErrNetworkNameMismatch},
		{"per-client, not requested", custom.ID, "", "ETHERNET", nil},
		{"per-client, matching", custom.ID, "ETHERNET", "ETHERNET", nil},
		{"per-client, mismatch", custom.ID, "WLAN", "", ErrNetworkNameMismatch},
		{"plain HTTP uses the default", 0, "", "WLAN", nil},
	}
	wantSQN := uint64(0)
	for _, tt := range tests {
		a, err := s.Allocate(ctx, AllocateRequest{
			IMSI: sub.IMSI, ClientID: tt.clientID, N: 1,
			NetworkName: tt.requested, DefaultNetworkName: "WLAN",
		})
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
			continue
		}
		if err == nil {
			wantSQN += 32
			if a.NetworkName != tt.want {
				t.Errorf("%s: NetworkName = %q, want %q", tt.name, a.NetworkName, tt.want)
			}
		}
	}
	// Network Name の不一致では SQN を進めない。
	if got, _ := s.GetSubscriber(ctx, sub.IMSI); got.SQN != wantSQN {
		t.Errorf("SQN = %d, want %d", got.SQN, wantSQN)
	}
}

// 同時に払い出しても同じ SQN を二重に払い出さない。
func TestAllocateConcurrent(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	sub := testSubscriber("440100000000060", aka.SQNInc33)
	sub.AllowPlain = true
	if err := s.CreateSubscriber(ctx, sub); err != nil {
		t.Fatal(err)
	}

	const workers, perWorker, n = 16, 25, 3
	var (
		mu   sync.Mutex
		seen = map[uint64]bool{}
		wg   sync.WaitGroup
	)
	for range workers {
		wg.Go(func() {
			for range perWorker {
				a, err := s.Allocate(context.Background(), AllocateRequest{IMSI: sub.IMSI, N: n})
				if err != nil {
					t.Error(err)
					return
				}
				sqns, _ := a.SQNType.Sequence(a.Base, n)
				mu.Lock()
				for _, sqn := range sqns {
					if seen[sqn] {
						t.Errorf("SQN %d allocated twice", sqn)
					}
					seen[sqn] = true
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(seen) != workers*perWorker*n {
		t.Errorf("allocated %d distinct SQNs, want %d", len(seen), workers*perWorker*n)
	}
}

func TestClientLifecycle(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	cert := testCert(t, "radius")
	c, err := s.CreateClient(ctx, NewClient{Name: "radius", Cert: cert, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != 1 || !c.Enabled || c.Fingerprint != certs.Fingerprint(cert) {
		t.Errorf("CreateClient = %+v", c)
	}
	if _, err := s.CreateClient(ctx, NewClient{Name: "again", Cert: cert, Enabled: true}); !errors.Is(err, ErrCertRegistered) {
		t.Errorf("same certificate: err = %v, want ErrCertRegistered", err)
	}

	got, err := s.ClientByFingerprint(ctx, c.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != c.ID || got.Name != "radius" || !got.NotAfter.Equal(c.NotAfter) {
		t.Errorf("ClientByFingerprint = %+v", got)
	}
	if parsed, err := certs.ParsePEM([]byte(got.CertPEM)); err != nil || certs.Fingerprint(parsed) != c.Fingerprint {
		t.Errorf("stored PEM does not round-trip: %v", err)
	}
	if _, err := s.ClientByFingerprint(ctx, "00"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown fingerprint: err = %v, want ErrNotFound", err)
	}

	c2 := addClient(t, s, "second", "")
	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != c.ID || list[1].ID != c2.ID {
		t.Errorf("ListClients = %+v", list)
	}

	// 削除すると、許可集合からも取り除かれる。
	const subs = purgeBatch + 20 // 複数バッチにまたがらせる
	for i := range subs {
		sub := testSubscriber(fmt.Sprintf("44010%010d", i), aka.SQNInc32)
		sub.AllowedClientIDs = []int64{c.ID, c2.ID}
		if err := s.CreateSubscriber(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClientByFingerprint(ctx, c.Fingerprint); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: err = %v, want ErrNotFound", err)
	}
	if err := s.DeleteClient(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice: err = %v, want ErrNotFound", err)
	}
	if err := s.PurgeClientFromSubscribers(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	for i := range subs {
		sub, err := s.GetSubscriber(ctx, fmt.Sprintf("44010%010d", i))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(sub.AllowedClientIDs, []int64{c2.ID}) {
			t.Fatalf("subscriber %s: AllowedClientIDs = %v, want [%d]", sub.IMSI, sub.AllowedClientIDs, c2.ID)
		}
	}

	// 削除したクライアントの ID も、登録に失敗して欠番になった ID も再利用しない。
	c3 := addClient(t, s, "third", "")
	if c3.ID <= c2.ID {
		t.Errorf("new client ID = %d, want greater than %d", c3.ID, c2.ID)
	}
}

func TestServerCertificate(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	if _, err := s.ServerCertificate(ctx, CertSlotAV); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty store: err = %v, want ErrNotFound", err)
	}
	created, err := s.InitServerCertificate(ctx, CertSlotAV, []byte("cert1"), []byte("key1"), CertSourceSelfSigned)
	if err != nil || !created {
		t.Fatalf("first init: created = %v, err = %v", created, err)
	}
	// 既にあれば上書きしない。
	created, err = s.InitServerCertificate(ctx, CertSlotAV, []byte("cert2"), []byte("key2"), CertSourceSelfSigned)
	if err != nil || created {
		t.Fatalf("second init: created = %v, err = %v", created, err)
	}
	c, err := s.ServerCertificate(ctx, CertSlotAV)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.CertPEM) != "cert1" || string(c.KeyPEM) != "key1" || c.Source != CertSourceSelfSigned {
		t.Errorf("ServerCertificate = %+v", c)
	}

	// 保存先ごとに独立している。
	if _, err := s.ServerCertificate(ctx, CertSlotAdmin); !errors.Is(err, ErrNotFound) {
		t.Errorf("admin slot: err = %v, want ErrNotFound", err)
	}

	if err := s.SetServerCertificate(ctx, CertSlotAV, []byte("cert3"), []byte("key3"), CertSourceUploaded); err != nil {
		t.Fatal(err)
	}
	c, err = s.ServerCertificate(ctx, CertSlotAV)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.CertPEM) != "cert3" || c.Source != CertSourceUploaded || c.UpdatedAt.IsZero() {
		t.Errorf("after set: %+v", c)
	}
}

func TestUpdateSubscriber(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	c1 := addClient(t, s, "c1", "")
	c2 := addClient(t, s, "c2", "")

	sub := testSubscriber("440100000000070", aka.SQNInc32)
	sub.AllowedClientIDs = []int64{c1.ID}
	if err := s.CreateSubscriber(ctx, sub); err != nil {
		t.Fatal(err)
	}

	// 指定した項目だけを変更する。
	err := s.UpdateSubscriber(ctx, sub.IMSI, SubscriberPatch{
		SQN:        new(uint64(0x1000)),
		AllowPlain: new(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSubscriber(ctx, sub.IMSI)
	if err != nil {
		t.Fatal(err)
	}
	if got.SQN != 0x1000 || !got.AllowPlain || got.AMF != 0x8000 || got.SQNType != aka.SQNInc32 ||
		string(got.Ki) != string(sub.Ki) || !slices.Equal(got.AllowedClientIDs, []int64{c1.ID}) {
		t.Errorf("after partial update: %+v", got)
	}

	// 許可クライアントは集合全体を置き換える。空にもできる。
	inc33 := aka.SQNInc33
	err = s.UpdateSubscriber(ctx, sub.IMSI, SubscriberPatch{
		Ki: []byte("KKKKKKKKKKKKKKKK"), OPc: []byte("OOOOOOOOOOOOOOOO"),
		AMF: new(uint16(0x9001)), SQNType: &inc33, AllowedClientIDs: &[]int64{c2.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetSubscriber(ctx, sub.IMSI)
	if string(got.Ki) != "KKKKKKKKKKKKKKKK" || string(got.OPc) != "OOOOOOOOOOOOOOOO" || got.AMF != 0x9001 ||
		got.SQNType != aka.SQNInc33 || !slices.Equal(got.AllowedClientIDs, []int64{c2.ID}) || got.SQN != 0x1000 {
		t.Errorf("after full update: %+v", got)
	}
	if err := s.UpdateSubscriber(ctx, sub.IMSI, SubscriberPatch{AllowedClientIDs: &[]int64{}}); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetSubscriber(ctx, sub.IMSI); len(got.AllowedClientIDs) != 0 {
		t.Errorf("after clearing clients: %v", got.AllowedClientIDs)
	}

	if err := s.UpdateSubscriber(ctx, sub.IMSI, SubscriberPatch{AllowedClientIDs: &[]int64{9999}}); !errors.Is(err, ErrUnknownClient) {
		t.Errorf("unknown client: err = %v, want ErrUnknownClient", err)
	}
	if err := s.UpdateSubscriber(ctx, "440100000000099", SubscriberPatch{AllowPlain: new(true)}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown subscriber: err = %v, want ErrNotFound", err)
	}
	// 存在しない加入者への変更で、キーを作ってしまわない。
	if _, err := s.GetSubscriber(ctx, "440100000000099"); !errors.Is(err, ErrNotFound) {
		t.Errorf("update created a subscriber: err = %v", err)
	}
}

func TestListSubscribers(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	imsis := []string{"440100000000001", "440100000000002", "440100000000003", "440200000000001", "440200000000002", "99999"}
	for _, imsi := range slices.Backward(imsis) { // 登録順に依らず辞書順で返ることを確かめる
		if err := s.CreateSubscriber(ctx, testSubscriber(imsi, aka.SQNInc32)); err != nil {
			t.Fatal(err)
		}
	}
	list := func(prefix, cursor string, limit int) ([]string, int64, string) {
		t.Helper()
		page, err := s.ListSubscribers(ctx, prefix, cursor, limit)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, len(page.Items))
		for i, sub := range page.Items {
			got[i] = sub.IMSI
		}
		return got, page.Total, page.NextCursor
	}

	// カーソルで全件をたどれる。
	var all []string
	cursor := ""
	for {
		got, total, next := list("", cursor, 4)
		if total != int64(len(imsis)) {
			t.Fatalf("total = %d, want %d", total, len(imsis))
		}
		all = append(all, got...)
		if next == "" {
			break
		}
		cursor = next
	}
	if !slices.Equal(all, imsis) {
		t.Errorf("paged listing = %v, want %v", all, imsis)
	}

	// ちょうど limit 件のときは次のページを示さない。
	if got, _, next := list("", "", len(imsis)); len(got) != len(imsis) || next != "" {
		t.Errorf("exact page: %d items, next = %q", len(got), next)
	}

	// 前方一致。total は一致した件数。
	got, total, next := list("4402", "", 10)
	if !slices.Equal(got, imsis[3:5]) || total != 2 || next != "" {
		t.Errorf("prefix 4402: %v, total %d, next %q", got, total, next)
	}
	got, total, next = list("4401", "", 2)
	if !slices.Equal(got, imsis[0:2]) || total != 3 || next != imsis[1] {
		t.Errorf("prefix 4401 page 1: %v, total %d, next %q", got, total, next)
	}
	got, _, next = list("4401", next, 2)
	if !slices.Equal(got, imsis[2:3]) || next != "" {
		t.Errorf("prefix 4401 page 2: %v, next %q", got, next)
	}
	if got, total, _ := list("5", "", 10); len(got) != 0 || total != 0 {
		t.Errorf("no match: %v, total %d", got, total)
	}

	if n, err := s.CountSubscribers(ctx); err != nil || n != int64(len(imsis)) {
		t.Errorf("CountSubscribers = %d, %v", n, err)
	}
}

func TestUpdateClientAndReplaceCertificate(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	c := addClient(t, s, "radius", "")
	other := addClient(t, s, "other", "")

	if err := s.UpdateClient(ctx, c.ID, ClientPatch{Name: new("radius-2"), Enabled: new(false), NetworkName: new("ETHERNET")}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetClient(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "radius-2" || got.Enabled || got.NetworkName != "ETHERNET" || got.Fingerprint != c.Fingerprint {
		t.Errorf("after update: %+v", got)
	}
	if err := s.UpdateClient(ctx, 9999, ClientPatch{Name: new("x")}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown client: err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetClient(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("update created a client: err = %v", err)
	}

	// 証明書の差し替え。ID は変わらず、古い証明書では引けなくなる。
	newCert := testCert(t, "radius-renewed")
	if err := s.ReplaceClientCertificate(ctx, c.ID, newCert); err != nil {
		t.Fatal(err)
	}
	got, err = s.ClientByFingerprint(ctx, certs.Fingerprint(newCert))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != c.ID || got.Name != "radius-2" || !got.NotAfter.Equal(newCert.NotAfter.UTC().Truncate(time.Second)) {
		t.Errorf("after replace: %+v", got)
	}
	if _, err := s.ClientByFingerprint(ctx, c.Fingerprint); !errors.Is(err, ErrNotFound) {
		t.Errorf("old fingerprint: err = %v, want ErrNotFound", err)
	}

	// 同じ証明書をもう一度指定しても成功する。
	if err := s.ReplaceClientCertificate(ctx, c.ID, newCert); err != nil {
		t.Errorf("same certificate again: %v", err)
	}
	// 別のクライアントが使っている証明書には差し替えられない。
	otherCert, err := certs.ParsePEM([]byte(other.CertPEM))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceClientCertificate(ctx, c.ID, otherCert); !errors.Is(err, ErrCertRegistered) {
		t.Errorf("certificate of another client: err = %v, want ErrCertRegistered", err)
	}
	if got, _ := s.ClientByFingerprint(ctx, other.Fingerprint); got.ID != other.ID {
		t.Errorf("other client's fingerprint now maps to %d", got.ID)
	}
	if err := s.ReplaceClientCertificate(ctx, 9999, testCert(t, "x")); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown client: err = %v, want ErrNotFound", err)
	}

	ids, err := s.ClientIDs(ctx)
	if err != nil || !slices.Equal(ids, []int64{c.ID, other.ID}) {
		t.Errorf("ClientIDs = %v, %v", ids, err)
	}
	if n, err := s.CountClients(ctx); err != nil || n != 2 {
		t.Errorf("CountClients = %d, %v", n, err)
	}
}

func TestAudit(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	if got, next, err := s.ListAudit(ctx, "", 10); err != nil || len(got) != 0 || next != "" {
		t.Errorf("empty: %v, %q, %v", got, next, err)
	}
	for i := range 5 {
		e := AuditEntry{Operator: "alice", MgmtClient: "bff", Action: "subscriber.create", Target: fmt.Sprint(i), Detail: `{"n":1}`, TraceID: "t" + fmt.Sprint(i)}
		if err := s.AppendAudit(ctx, e, 1000); err != nil {
			t.Fatal(err)
		}
	}

	// 新しい順に返り、nextBefore で続きをたどれる。
	var targets []string
	before := ""
	for {
		got, next, err := s.ListAudit(ctx, before, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range got {
			if e.Operator != "alice" || e.MgmtClient != "bff" || e.Action != "subscriber.create" || e.Detail != `{"n":1}` || e.TraceID != "t"+e.Target {
				t.Errorf("entry = %+v", e)
			}
			if time.Since(e.Time) > time.Minute || e.ID == "" {
				t.Errorf("entry time/id = %v / %q", e.Time, e.ID)
			}
			targets = append(targets, e.Target)
		}
		if next == "" {
			break
		}
		before = next
	}
	if want := []string{"4", "3", "2", "1", "0"}; !slices.Equal(targets, want) {
		t.Errorf("targets = %v, want %v", targets, want)
	}

	// trace_id を持たない以前のエントリは、トレースID を空として読む。
	old := s.c.B().Xadd().Key(keyAudit).Id("*").FieldValue().
		FieldValue("operator", "bob").
		FieldValue("mgmt_client", "bff").
		FieldValue("action", "client.create").
		FieldValue("target", "9").
		FieldValue("detail", "").Build()
	if err := s.c.Do(ctx, old).Error(); err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.ListAudit(ctx, "", 1); err != nil || len(got) != 1 || got[0].Operator != "bob" || got[0].TraceID != "" {
		t.Errorf("entry without trace_id = %+v, %v", got, err)
	}
}
