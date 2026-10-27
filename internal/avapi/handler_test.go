package avapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wmnsk/milenage"

	"github.com/oyaguma3/aka-vecgen/internal/aka"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

var testCreds = aka.Credentials{
	Ki:  []byte{0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc},
	OPc: []byte{0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf},
	AMF: 0x8000,
}

// fakeAllocator は 1 加入者分の払い出しを模す。
type fakeAllocator struct {
	sqn         uint64
	sqnType     aka.SQNType
	networkName string
	err         error
	calls       []store.AllocateRequest
}

func (f *fakeAllocator) Allocate(_ context.Context, req store.AllocateRequest) (store.Allocation, error) {
	f.calls = append(f.calls, req)
	if f.err != nil {
		return store.Allocation{}, f.err
	}
	if req.NetworkName != "" && req.NetworkName != f.networkName {
		return store.Allocation{}, store.ErrNetworkNameMismatch
	}
	if req.ResyncSQN != nil {
		f.sqn = *req.ResyncSQN
	}
	a := store.Allocation{Base: f.sqn, Credentials: testCreds, SQNType: f.sqnType, NetworkName: f.networkName}
	if req.N > 0 {
		sqns, _ := f.sqnType.Sequence(f.sqn, req.N)
		f.sqn = sqns[len(sqns)-1]
	}
	return a, nil
}

func newTestHandler(f *fakeAllocator) http.Handler {
	h := &Handler{
		Allocator: f,
		Log:       slog.New(slog.DiscardHandler),
		ClientID:  func(*http.Request) int64 { return 7 },
	}
	return h.Routes()
}

func post(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

const basePath = "/nudm-ueau/v1/imsi-440100123456789/hss-security-information/"

func decodeVectors(t *testing.T, rec *httptest.ResponseRecorder) []authVector {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var resp generateAVResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.HSSAuthenticationVectors
}

// checkVector は、返されたベクターが期待する SQN で生成されたものかを再計算して確かめる。
func checkVector(t *testing.T, av authVector, sqn uint64) aka.Vector {
	t.Helper()
	rnd, err := hex.DecodeString(av.RAND)
	if err != nil || len(rnd) != 16 {
		t.Fatalf("bad rand %q", av.RAND)
	}
	want, err := aka.Generate(testCreds, rnd, sqn)
	if err != nil {
		t.Fatal(err)
	}
	if av.AUTN != hex.EncodeToString(want.AUTN) {
		t.Errorf("AUTN = %s, want %s (SQN %d)", av.AUTN, hex.EncodeToString(want.AUTN), sqn)
	}
	if av.XRES != hex.EncodeToString(want.XRES) {
		t.Errorf("XRES = %s, want %s", av.XRES, hex.EncodeToString(want.XRES))
	}
	return want
}

func TestGenerateEAPAKA(t *testing.T) {
	f := &fakeAllocator{sqn: 64, sqnType: aka.SQNInc32, networkName: "WLAN"}
	rec := post(t, newTestHandler(f), basePath+"eap-aka/generate-av", `{"hssAuthType":"EAP_AKA","numOfRequestedVectors":3}`)
	vectors := decodeVectors(t, rec)
	if len(vectors) != 3 {
		t.Fatalf("got %d vectors, want 3", len(vectors))
	}

	rands := map[string]bool{}
	for i, av := range vectors {
		want := checkVector(t, av, 64+32*uint64(i+1))
		if av.AVType != "EAP_AKA" {
			t.Errorf("avType = %q", av.AVType)
		}
		if av.CK != hex.EncodeToString(want.CK) || av.IK != hex.EncodeToString(want.IK) {
			t.Errorf("vector %d: CK/IK mismatch", i)
		}
		if av.CKPrime != "" || av.IKPrime != "" {
			t.Errorf("vector %d: EAP_AKA must not carry ckPrime/ikPrime", i)
		}
		rands[av.RAND] = true
	}
	if len(rands) != 3 {
		t.Error("RAND is reused within a batch")
	}
	if strings.Contains(rec.Body.String(), "ckPrime") {
		t.Errorf("body has ckPrime: %s", rec.Body)
	}

	if len(f.calls) != 1 {
		t.Fatalf("Allocate called %d times, want 1", len(f.calls))
	}
	want := store.AllocateRequest{IMSI: "440100123456789", ClientID: 7, N: 3, DefaultNetworkName: "WLAN"}
	if f.calls[0] != want {
		t.Errorf("AllocateRequest = %+v, want %+v", f.calls[0], want)
	}
}

func TestGenerateUMTSAKA(t *testing.T) {
	f := &fakeAllocator{sqnType: aka.SQNInc1}
	rec := post(t, newTestHandler(f), basePath+"umts-aka/generate-av", `{"hssAuthType":"UMTS_AKA","numOfRequestedVectors":1}`)
	vectors := decodeVectors(t, rec)
	if len(vectors) != 1 || vectors[0].AVType != "UMTS_AKA" || vectors[0].CK == "" {
		t.Errorf("vectors = %+v", vectors)
	}
	checkVector(t, vectors[0], 1)
}

func TestGenerateEAPAKAPrime(t *testing.T) {
	for _, body := range []string{
		`{"hssAuthType":"EAP_AKA_PRIME","numOfRequestedVectors":2}`,
		`{"hssAuthType":"EAP_AKA_PRIME","numOfRequestedVectors":2,"anId":"ETHERNET"}`,
	} {
		f := &fakeAllocator{sqnType: aka.SQNInc33, networkName: "ETHERNET"}
		rec := post(t, newTestHandler(f), basePath+"eap-aka-prime/generate-av", body)
		vectors := decodeVectors(t, rec)
		if len(vectors) != 2 {
			t.Fatalf("got %d vectors, want 2", len(vectors))
		}
		for i, av := range vectors {
			v := checkVector(t, av, []uint64{33, 65}[i])
			ckPrime, ikPrime := aka.DerivePrime(v, "ETHERNET")
			if av.AVType != "EAP_AKA_PRIME" || av.CKPrime != hex.EncodeToString(ckPrime) || av.IKPrime != hex.EncodeToString(ikPrime) {
				t.Errorf("vector %d = %+v", i, av)
			}
			if av.CK != "" || av.IK != "" {
				t.Errorf("vector %d: EAP_AKA_PRIME must not carry ck/ik", i)
			}
		}
	}
}

func TestGenerateIgnoresUnusedFields(t *testing.T) {
	f := &fakeAllocator{sqnType: aka.SQNInc32, networkName: "WLAN"}
	body := `{"hssAuthType":"EAP_AKA","numOfRequestedVectors":1,"requestingNodeType":"WLAN_AAA_SERVER",
		"servingNetworkId":{"mcc":"440","mnc":"10"},"supportedFeatures":"0","anId":"HRPD"}`
	rec := post(t, newTestHandler(f), basePath+"eap-aka/generate-av", body)
	decodeVectors(t, rec)
	// anId は EAP-AKA' 以外では照合しない。
	if f.calls[0].NetworkName != "" {
		t.Errorf("NetworkName = %q, want empty for EAP_AKA", f.calls[0].NetworkName)
	}
}

func TestGenerateResync(t *testing.T) {
	rnd := bytes.Repeat([]byte{0x5a}, 16)
	const sqnMS = 32 * 1000
	m := milenage.NewWithOPc(testCreds.Ki, testCreds.OPc, rnd, sqnMS, testCreds.AMF)
	auts, err := m.GenerateAUTS()
	if err != nil {
		t.Fatal(err)
	}
	body := func(auts []byte) string {
		return `{"hssAuthType":"EAP_AKA","numOfRequestedVectors":2,"resynchronizationInfo":{"rand":"` +
			hex.EncodeToString(rnd) + `","auts":"` + hex.EncodeToString(auts) + `"}}`
	}

	f := &fakeAllocator{sqn: 64, sqnType: aka.SQNInc32}
	rec := post(t, newTestHandler(f), basePath+"eap-aka/generate-av", body(auts))
	vectors := decodeVectors(t, rec)
	checkVector(t, vectors[0], sqnMS+32)
	checkVector(t, vectors[1], sqnMS+64)
	if len(f.calls) != 2 || f.calls[0].N != 0 || f.calls[0].ResyncSQN != nil {
		t.Fatalf("calls = %+v, want a probe (N=0) first", f.calls)
	}
	if f.calls[1].N != 2 || f.calls[1].ResyncSQN == nil || *f.calls[1].ResyncSQN != sqnMS {
		t.Errorf("second call = %+v", f.calls[1])
	}

	// AUTS が不正なら SQN を変更しない。
	bad := bytes.Clone(auts)
	bad[13] ^= 0xff
	f = &fakeAllocator{sqn: 64, sqnType: aka.SQNInc32}
	rec = post(t, newTestHandler(f), basePath+"eap-aka/generate-av", body(bad))
	checkProblem(t, rec, http.StatusForbidden, causeAuthRejected)
	if len(f.calls) != 1 || f.sqn != 64 {
		t.Errorf("after bad AUTS: calls = %d, sqn = %d", len(f.calls), f.sqn)
	}
}

func checkProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, cause string) {
	t.Helper()
	if rec.Code != status {
		t.Errorf("status = %d, want %d (body %s)", rec.Code, status, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var pd problemDetails
	if err := json.Unmarshal(rec.Body.Bytes(), &pd); err != nil {
		t.Fatalf("body is not ProblemDetails: %v (%s)", err, rec.Body)
	}
	if pd.Cause != cause || pd.Status != status {
		t.Errorf("problem = %+v, want status %d cause %s", pd, status, cause)
	}
}

func TestGenerateRejectsBadRequests(t *testing.T) {
	const ok = `{"hssAuthType":"EAP_AKA","numOfRequestedVectors":1}`
	hex32, hex28 := strings.Repeat("0", 32), strings.Repeat("0", 28)
	tests := []struct {
		name   string
		path   string
		body   string
		status int
		cause  string
	}{
		{"bad JSON", basePath + "eap-aka/generate-av", `{`, 400, causeInvalidMsgFormat},
		{"wrong JSON type", basePath + "eap-aka/generate-av", `{"hssAuthType":"EAP_AKA","numOfRequestedVectors":"1"}`, 400, causeInvalidMsgFormat},
		{"no hssAuthType", basePath + "eap-aka/generate-av", `{"numOfRequestedVectors":1}`, 400, causeMandatoryIEMissing},
		{"no numOfRequestedVectors", basePath + "eap-aka/generate-av", `{"hssAuthType":"EAP_AKA"}`, 400, causeMandatoryIEMissing},
		{"path and body differ", basePath + "eap-aka-prime/generate-av", ok, 400, causeMandatoryIEIncorrect},
		{"zero vectors", basePath + "eap-aka/generate-av", `{"hssAuthType":"EAP_AKA","numOfRequestedVectors":0}`, 400, causeMandatoryIEIncorrect},
		{"six vectors", basePath + "eap-aka/generate-av", `{"hssAuthType":"EAP_AKA","numOfRequestedVectors":6}`, 400, causeMandatoryIEIncorrect},
		{"unknown auth type", basePath + "foo/generate-av", ok, 400, causeMandatoryIEIncorrect},
		{"unsupported auth type", basePath + "eps-aka/generate-av", `{"hssAuthType":"EPS_AKA","numOfRequestedVectors":1}`, 501, causeAuthTypeNotSupported},
		{"bad supi", "/nudm-ueau/v1/nai-foo/hss-security-information/eap-aka/generate-av", ok, 400, causeMandatoryIEIncorrect},
		{"short imsi", "/nudm-ueau/v1/imsi-1234/hss-security-information/eap-aka/generate-av", ok, 400, causeMandatoryIEIncorrect},
		{"bad resync rand", basePath + "eap-aka/generate-av",
			`{"hssAuthType":"EAP_AKA","numOfRequestedVectors":1,"resynchronizationInfo":{"rand":"zz","auts":"` + hex28 + `"}}`, 400, causeOptionalIEIncorrect},
		{"bad resync auts", basePath + "eap-aka/generate-av",
			`{"hssAuthType":"EAP_AKA","numOfRequestedVectors":1,"resynchronizationInfo":{"rand":"` + hex32 + `","auts":"00"}}`, 400, causeOptionalIEIncorrect},
		{"empty anId", basePath + "eap-aka-prime/generate-av",
			`{"hssAuthType":"EAP_AKA_PRIME","numOfRequestedVectors":1,"anId":""}`, 400, causeOptionalIEIncorrect},
	}
	for _, tt := range tests {
		f := &fakeAllocator{sqnType: aka.SQNInc32, networkName: "WLAN"}
		rec := post(t, newTestHandler(f), tt.path, tt.body)
		t.Run(tt.name, func(t *testing.T) {
			checkProblem(t, rec, tt.status, tt.cause)
			if len(f.calls) != 0 {
				t.Errorf("Allocate was called for an invalid request")
			}
		})
	}
}

func TestGenerateMapsAllocatorErrors(t *testing.T) {
	tests := []struct {
		err    error
		status int
		cause  string
	}{
		{store.ErrNotFound, 404, causeUserNotFound},
		{store.ErrForbidden, 403, causeAuthRejected},
		{errors.New("valkey is down: secret detail"), 500, causeSystemFailure},
	}
	for _, tt := range tests {
		f := &fakeAllocator{err: tt.err}
		rec := post(t, newTestHandler(f), basePath+"eap-aka/generate-av", `{"hssAuthType":"EAP_AKA","numOfRequestedVectors":1}`)
		checkProblem(t, rec, tt.status, tt.cause)
		// 内部エラーの詳細はクライアントに返さない。
		if strings.Contains(rec.Body.String(), "secret detail") {
			t.Errorf("internal error detail leaked: %s", rec.Body)
		}
	}

	// anId がサーバー側の設定値と一致しない。
	f := &fakeAllocator{sqnType: aka.SQNInc32, networkName: "WLAN"}
	rec := post(t, newTestHandler(f), basePath+"eap-aka-prime/generate-av",
		`{"hssAuthType":"EAP_AKA_PRIME","numOfRequestedVectors":1,"anId":"HRPD"}`)
	checkProblem(t, rec, 400, causeOptionalIEIncorrect)
}

func TestMethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestHandler(&fakeAllocator{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, basePath+"eap-aka/generate-av", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d, want 405", rec.Code)
	}
}

func TestTraceID(t *testing.T) {
	var logs bytes.Buffer
	h := (&Handler{
		Allocator: &fakeAllocator{sqn: 64, sqnType: aka.SQNInc32, networkName: "WLAN"},
		Log:       slog.New(slog.NewJSONHandler(&logs, nil)),
		ClientID:  func(*http.Request) int64 { return 7 },
	}).Routes()
	send := func(traceID, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, basePath+"eap-aka/generate-av", strings.NewReader(body))
		if traceID != "" {
			req.Header.Set("X-Trace-ID", traceID)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 呼び出し元のトレースID をそのまま返し、ログに残す（成功・拒否のどちらでも）。
	for _, body := range []string{`{"hssAuthType":"EAP_AKA","numOfRequestedVectors":1}`, `{"hssAuthType":"EAP_AKA","numOfRequestedVectors":0}`} {
		logs.Reset()
		rec := send("vgw-trace-0001", body)
		if got := rec.Header().Get("X-Trace-ID"); got != "vgw-trace-0001" {
			t.Errorf("X-Trace-ID = %q, want vgw-trace-0001 (body %s)", got, body)
		}
		if !strings.Contains(logs.String(), `"trace_id":"vgw-trace-0001"`) {
			t.Errorf("log does not contain the trace id: %s", logs.String())
		}
	}

	// ない・形の違う値なら採番する。
	for _, in := range []string{"", "has space"} {
		logs.Reset()
		got := send(in, `{"hssAuthType":"EAP_AKA","numOfRequestedVectors":1}`).Header().Get("X-Trace-ID")
		if len(got) != 32 || got == in {
			t.Errorf("X-Trace-ID for %q = %q, want a generated id", in, got)
		}
		if !strings.Contains(logs.String(), `"trace_id":"`+got+`"`) {
			t.Errorf("log does not contain the generated trace id %q: %s", got, logs.String())
		}
	}
}
