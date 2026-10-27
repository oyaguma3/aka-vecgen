package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/oyaguma3/aka-vecgen/internal/aka"
	"github.com/oyaguma3/aka-vecgen/internal/certs"
)

func TestCredentialsEncryptedAtRest(t *testing.T) {
	// Valkey には Ki・OPc を平文で置かない（設計概要 §8.1）。
	s := openTestStore(t)
	sub := testSubscriber("440100000000101", aka.SQNInc32)
	createAllowed(t, s, sub)

	f, err := s.c.Do(t.Context(), s.c.B().Hgetall().Key(subKey(sub.IMSI)).Build()).AsStrMap()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f["ki"]; ok {
		t.Error("plaintext ki is stored")
	}
	if _, ok := f["opc"]; ok {
		t.Error("plaintext opc is stored")
	}
	if f["cred_kek"] != s.KEKID() || len(f["cred"]) != 12+32+16 {
		t.Errorf("cred_kek = %q, len(cred) = %d", f["cred_kek"], len(f["cred"]))
	}
	if bytes.Contains([]byte(f["cred"]), sub.Ki) || bytes.Contains([]byte(f["cred"]), sub.OPc) {
		t.Error("cred contains the plaintext key")
	}
}

func TestSetupKEK(t *testing.T) {
	ctx := t.Context()
	s := openTestStore(t) // KEK 1 で初めての起動を済ませている
	k1, k2 := testKEK(t, 1), testKEK(t, 2)

	if init, err := s.SetupKEK(ctx, k1); err != nil || init {
		t.Errorf("second SetupKEK = %v, %v; want false, nil", init, err)
	}
	if _, err := s.SetupKEK(ctx, k2); !errors.Is(err, ErrKEKMismatch) {
		t.Errorf("SetupKEK(another KEK) = %v, want ErrKEKMismatch", err)
	}

	// 確認の値が壊れていれば合わないとする
	if err := s.c.Do(ctx, s.c.B().Set().Key(keyKEKCheck).Value("broken").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetupKEK(ctx, k1); !errors.Is(err, ErrKEKMismatch) {
		t.Errorf("SetupKEK(broken check) = %v, want ErrKEKMismatch", err)
	}

	// cfg:kek がないのに加入者がいれば、初めての起動として扱わない（確認事項 D4）
	createAllowed(t, s, testSubscriber("440100000000102", aka.SQNInc32))
	if err := s.c.Do(ctx, s.c.B().Del().Key(keyKEK, keyKEKCheck).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetupKEK(ctx, k2); !errors.Is(err, ErrKEKMissing) {
		t.Errorf("SetupKEK(missing cfg:kek with data) = %v, want ErrKEKMissing", err)
	}

	// rotate-kek の途中なら起動しない
	if err := s.c.Do(ctx, s.c.B().Set().Key(keyKEKRotation).Value("a:b").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetupKEK(ctx, k1); !errors.Is(err, ErrKEKRotationInProgress) {
		t.Errorf("SetupKEK(during rotation) = %v, want ErrKEKRotationInProgress", err)
	}
}

func TestUnreadableCredentials(t *testing.T) {
	// 平文の行・別の KEK の行・別の加入者から移した暗号文は ErrCredInvalid（確認事項 D1）。
	ctx := t.Context()
	s := openTestStore(t)
	a := testSubscriber("440100000000111", aka.SQNInc32)
	clientID := createAllowed(t, s, a)
	b := testSubscriber("440100000000112", aka.SQNInc32)
	b.AllowedClientIDs = []int64{clientID}
	if err := s.CreateSubscriber(ctx, b); err != nil {
		t.Fatal(err)
	}
	alloc := func(imsi string) error {
		_, err := s.Allocate(ctx, AllocateRequest{IMSI: imsi, ClientID: clientID, N: 1, DefaultNetworkName: "WLAN"})
		return err
	}
	if err := alloc(a.IMSI); err != nil {
		t.Fatalf("Allocate(a) = %v", err)
	}

	hset := func(imsi string, kv ...string) {
		t.Helper()
		cmd := s.c.B().Hset().Key(subKey(imsi)).FieldValue()
		for i := 0; i < len(kv); i += 2 {
			cmd = cmd.FieldValue(kv[i], kv[i+1])
		}
		if err := s.c.Do(ctx, cmd.Build()).Error(); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := s.c.Do(ctx, s.c.B().Hgetall().Key(subKey(a.IMSI)).Build()).AsStrMap()

	// b の行に a の暗号文を移しても復号できない（AAD に IMSI が入っている）
	hset(b.IMSI, "cred", f["cred"], "cred_kek", f["cred_kek"])
	if err := alloc(b.IMSI); !errors.Is(err, ErrCredInvalid) {
		t.Errorf("Allocate(moved cred) = %v, want ErrCredInvalid", err)
	}
	// 別の KEK の識別子
	hset(b.IMSI, "cred_kek", "0000000000000000")
	if err := alloc(b.IMSI); !errors.Is(err, ErrCredInvalid) {
		t.Errorf("Allocate(another kek) = %v, want ErrCredInvalid", err)
	}
	// 平文の行（2-1 までの形）
	if err := s.c.Do(ctx, s.c.B().Hdel().Key(subKey(b.IMSI)).Field("cred", "cred_kek").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	hset(b.IMSI, "ki", "00112233445566778899aabbccddeeff", "opc", "00112233445566778899aabbccddeeff")
	if err := alloc(b.IMSI); !errors.Is(err, ErrCredInvalid) {
		t.Errorf("Allocate(plaintext row) = %v, want ErrCredInvalid", err)
	}
	if _, _, err := s.SubscriberKeys(ctx, b.IMSI); !errors.Is(err, ErrCredInvalid) {
		t.Errorf("SubscriberKeys(plaintext row) = %v, want ErrCredInvalid", err)
	}
	if _, _, err := s.SubscriberKeys(ctx, "440100000000199"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SubscriberKeys(missing) = %v, want ErrNotFound", err)
	}
}

func TestServerCertificateEncrypted(t *testing.T) {
	ctx := t.Context()
	s := openTestStore(t)
	certPEM, keyPEM, err := certs.SelfSigned(certs.SelfSignedOptions{CommonName: "test", Hosts: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InitServerCertificate(ctx, CertSlotAV, certPEM, keyPEM, CertSourceSelfSigned); err != nil {
		t.Fatal(err)
	}
	f, _ := s.c.Do(ctx, s.c.B().Hgetall().Key(string(CertSlotAV)).Build()).AsStrMap()
	if _, ok := f["key_pem"]; ok || f["key_kek"] != s.KEKID() || bytes.Contains([]byte(f["key_enc"]), keyPEM) {
		t.Errorf("stored fields = %v", keysOfMap(f))
	}
	sc, err := s.ServerCertificate(ctx, CertSlotAV)
	if err != nil || !bytes.Equal(sc.KeyPEM, keyPEM) || !bytes.Equal(sc.CertPEM, certPEM) {
		t.Fatalf("ServerCertificate = %v", err)
	}

	// 暗号文を別の口（管理用）に移しても復号できない
	if err := s.c.Do(ctx, s.c.B().Hset().Key(string(CertSlotAdmin)).FieldValue().
		FieldValue("cert_pem", f["cert_pem"]).FieldValue("key_enc", f["key_enc"]).FieldValue("key_kek", f["key_kek"]).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ServerCertificate(ctx, CertSlotAdmin); !errors.Is(err, ErrCertKeyInvalid) {
		t.Errorf("ServerCertificate(moved key) = %v, want ErrCertKeyInvalid", err)
	}

	// 平文の秘密鍵の行（2-1 までの形）は読まない。置き換えると平文が残らない
	if err := s.c.Do(ctx, s.c.B().Del().Key(string(CertSlotAdmin)).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if err := s.c.Do(ctx, s.c.B().Hset().Key(string(CertSlotAdmin)).FieldValue().
		FieldValue("cert_pem", string(certPEM)).FieldValue("key_pem", string(keyPEM)).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ServerCertificate(ctx, CertSlotAdmin); !errors.Is(err, ErrCertKeyInvalid) {
		t.Errorf("ServerCertificate(plaintext key) = %v, want ErrCertKeyInvalid", err)
	}
	if err := s.SetServerCertificate(ctx, CertSlotAdmin, certPEM, keyPEM, CertSourceSelfSigned); err != nil {
		t.Fatal(err)
	}
	f, _ = s.c.Do(ctx, s.c.B().Hgetall().Key(string(CertSlotAdmin)).Build()).AsStrMap()
	if _, ok := f["key_pem"]; ok {
		t.Error("plaintext key_pem remains after SetServerCertificate")
	}
	if _, err := s.ServerCertificate(ctx, CertSlotAdmin); err != nil {
		t.Errorf("ServerCertificate after replace: %v", err)
	}
}

func keysOfMap(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestServing(t *testing.T) {
	ctx := t.Context()
	s := openTestStore(t)
	if err := s.MarkServing(ctx, "boot-a"); err != nil {
		t.Fatal(err)
	}
	ttl, _ := s.c.Do(ctx, s.c.B().Ttl().Key(keyServeAlive).Build()).AsInt64()
	if ttl <= 0 || ttl > 30 {
		t.Errorf("ttl = %d", ttl)
	}
	// 別の起動の印は消さない
	if err := s.ClearServing(ctx, "boot-b"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.c.Do(ctx, s.c.B().Exists().Key(keyServeAlive).Build()).AsInt64(); n != 1 {
		t.Error("ClearServing removed another boot's mark")
	}
	if err := s.ClearServing(ctx, "boot-a"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.c.Do(ctx, s.c.B().Exists().Key(keyServeAlive).Build()).AsInt64(); n != 0 {
		t.Error("ClearServing did not remove its mark")
	}
}

func TestRotateKEK(t *testing.T) {
	ctx := t.Context()
	s := openTestStore(t)
	k1, k2 := testKEK(t, 1), testKEK(t, 2)

	// 3 回に分けて読む数（rotateBatch は 500）の加入者と、サーバー証明書
	c := addClient(t, s, "rotate", "")
	const n = 1100
	for i := range n {
		sub := testSubscriber(fmt.Sprintf("44010%010d", i), aka.SQNInc32)
		sub.Ki = bytes.Repeat([]byte{byte(i)}, 16)
		sub.AllowedClientIDs = []int64{c.ID}
		if err := s.CreateSubscriber(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}
	certPEM, keyPEM, _ := certs.SelfSigned(certs.SelfSignedOptions{CommonName: "test", Hosts: []string{"localhost"}})
	if _, err := s.InitServerCertificate(ctx, CertSlotAV, certPEM, keyPEM, CertSourceSelfSigned); err != nil {
		t.Fatal(err)
	}
	// 平文の行（読めない行）が 1 つある
	if err := s.c.Do(ctx, s.c.B().Hdel().Key(subKey("440100000000007")).Field("cred", "cred_kek").Build()).Error(); err != nil {
		t.Fatal(err)
	}

	// serve が動いていれば断る（確認事項 D3）
	if err := s.MarkServing(ctx, "boot"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateKEK(ctx, k1, k2, nil); !errors.Is(err, ErrServeRunning) {
		t.Fatalf("RotateKEK while serving = %v, want ErrServeRunning", err)
	}
	if err := s.ClearServing(ctx, "boot"); err != nil {
		t.Fatal(err)
	}
	// 違う古い KEK では始めない
	if _, err := s.RotateKEK(ctx, testKEK(t, 3), k2, nil); !errors.Is(err, ErrKEKMismatch) {
		t.Fatalf("RotateKEK(wrong old) = %v, want ErrKEKMismatch", err)
	}

	// 1 回目の読みの後で止める（途中で止まった状態）
	cctx, cancel := context.WithCancel(ctx)
	_, err := s.RotateKEK(cctx, k1, k2, func(done, total int) { cancel() })
	if err == nil {
		t.Fatal("RotateKEK did not stop")
	}
	if _, err := s.SetupKEK(ctx, k1); !errors.Is(err, ErrKEKRotationInProgress) {
		t.Errorf("SetupKEK during rotation = %v, want ErrKEKRotationInProgress", err)
	}
	// 別の組の KEK でやり直すことはできない
	if _, err := s.RotateKEK(ctx, k1, testKEK(t, 4), nil); !errors.Is(err, ErrKEKRotationInProgress) {
		t.Errorf("RotateKEK(other new) = %v, want ErrKEKRotationInProgress", err)
	}

	// 同じ KEK でやり直すと続きから終わる
	res, err := s.RotateKEK(ctx, k1, k2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Finished || res.AlreadyNew == 0 || res.Rotated+res.AlreadyNew != n-1 || res.Invalid != 1 || res.Certificates != 1 {
		t.Errorf("result = %+v", res)
	}
	// もう一度やっても何もしない
	if res, err := s.RotateKEK(ctx, k1, k2, nil); err != nil || !res.Finished || res.Rotated != 0 {
		t.Errorf("RotateKEK again = %+v, %v", res, err)
	}

	// 新しい KEK で起動でき、古い KEK では起動できない
	if _, err := s.SetupKEK(ctx, k1); !errors.Is(err, ErrKEKMismatch) {
		t.Errorf("SetupKEK(old) = %v, want ErrKEKMismatch", err)
	}
	if _, err := s.SetupKEK(ctx, k2); err != nil {
		t.Fatalf("SetupKEK(new) = %v", err)
	}
	for _, i := range []int{0, 499, 500, 1099} {
		imsi := fmt.Sprintf("44010%010d", i)
		ki, _, err := s.SubscriberKeys(ctx, imsi)
		if err != nil || !bytes.Equal(ki, bytes.Repeat([]byte{byte(i)}, 16)) {
			t.Errorf("SubscriberKeys(%s) = %x, %v", imsi, ki, err)
		}
		if _, err := s.Allocate(ctx, AllocateRequest{IMSI: imsi, ClientID: c.ID, N: 1, DefaultNetworkName: "WLAN"}); err != nil {
			t.Errorf("Allocate(%s) after rotation: %v", imsi, err)
		}
	}
	if sc, err := s.ServerCertificate(ctx, CertSlotAV); err != nil || !bytes.Equal(sc.KeyPEM, keyPEM) {
		t.Errorf("ServerCertificate after rotation: %v", err)
	}
}
