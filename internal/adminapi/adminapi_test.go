package adminapi_test

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/oyaguma3/aka-vecgen/internal/adminapi"
	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/config"
	"github.com/oyaguma3/aka-vecgen/internal/logbuf"
	"github.com/oyaguma3/aka-vecgen/internal/server"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

// このテストは、ハンドラーからストアまでを実際の Valkey に対して通しで確かめる。
// 接続先を環境変数で指定したときだけ実行する。論理データベース 2 番の全データを消す。
const testDB = 2

const (
	testKi  = "465b5ce8b199b49faa5f0a2ee238a6bc"
	testOPc = "cd63cb71954a9f4e48a5994e37a02baf"
)

type env struct {
	t     *testing.T
	h     http.Handler
	store *store.Store
	log   *slog.Logger
}

func newEnv(t *testing.T) *env {
	t.Helper()
	addr := os.Getenv("VECGEN_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("VECGEN_TEST_VALKEY_ADDR is not set")
	}
	password := os.Getenv("VECGEN_TEST_VALKEY_PASSWORD")

	raw, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, Password: password, SelectDB: testDB, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.Do(t.Context(), raw.B().Flushdb().Build()).Error(); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(t.Context(), store.Options{Addr: addr, Password: password, DB: testDB})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	logs := logbuf.New(100)
	log := slog.New(logs.Handler(slog.NewTextHandler(io.Discard, nil)))
	srv, err := server.New(t.Context(), config.Config{AVTLSHosts: []string{"localhost"}}, st, log)
	if err != nil {
		t.Fatal(err)
	}
	h := &adminapi.Handler{
		Store:       st,
		Certs:       srv,
		Logs:        logs,
		Log:         log,
		MgmtClient:  func(*http.Request) string { return "test-bff" },
		Version:     "test",
		BootID:      "boot-1",
		StartedAt:   time.Now().UTC(),
		AuditMaxLen: 1000,
	}
	return &env{t: t, h: h.Routes(), store: st, log: log}
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// do はリクエストを送る。body が文字列ならそのまま、それ以外なら JSON にして送る。
func (e *env) do(method, path string, body any) response {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, "/admin/v2"+path, rd)
	req.Header.Set("X-Operator-Id", "alice")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return response{rec.Code, rec.Header(), rec.Body.Bytes()}
}

// decode は応答の状態コードを確かめ、本文を T として読む。
func decode[T any](t *testing.T, r response, wantStatus int) T {
	t.Helper()
	if r.status != wantStatus {
		t.Fatalf("status = %d, want %d (body %s)", r.status, wantStatus, r.body)
	}
	var v T
	if err := json.Unmarshal(r.body, &v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
	return v
}

type problemBody struct {
	Status        int    `json:"status"`
	Cause         string `json:"cause"`
	InvalidParams []struct {
		Param string `json:"param"`
	} `json:"invalidParams"`
}

// wantProblem は応答が期待する ProblemDetails かを確かめ、不正とされた項目名を返す。
func wantProblem(t *testing.T, r response, status int, cause string) []string {
	t.Helper()
	if ct := r.header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q (body %s)", ct, r.body)
	}
	p := decode[problemBody](t, r, status)
	if p.Cause != cause || p.Status != status {
		t.Errorf("problem = %s, want status %d cause %s", r.body, status, cause)
	}
	var params []string
	for _, ip := range p.InvalidParams {
		params = append(params, ip.Param)
	}
	slices.Sort(params)
	return params
}

type subscriber struct {
	IMSI             string    `json:"imsi"`
	State            string    `json:"state"`
	StateChangedAt   time.Time `json:"stateChangedAt"`
	SQN              string    `json:"sqn"`
	AMF              string    `json:"amf"`
	SQNType          string    `json:"sqnType"`
	AllowedClientIDs []int64   `json:"allowedClientIds"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type client struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	CertPEM           string    `json:"certPem"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	Subject           string    `json:"subject"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`
	Enabled           bool      `json:"enabled"`
	NetworkName       string    `json:"networkName"`
	CreatedAt         time.Time `json:"createdAt"`
}

type auditEntry struct {
	ID         string         `json:"id"`
	Time       time.Time      `json:"time"`
	Operator   string         `json:"operator"`
	MgmtClient string         `json:"mgmtClient"`
	Action     string         `json:"action"`
	Target     string         `json:"target"`
	TraceID    string         `json:"traceId"`
	Detail     map[string]any `json:"detail"`
}

type auditList struct {
	Items      []auditEntry `json:"items"`
	NextBefore string       `json:"nextBefore"`
}

func clientCertPEM(t *testing.T, name string, validFor time.Duration) (certPEM, keyPEM string) {
	t.Helper()
	c, k, err := certs.SelfSigned(certs.SelfSignedOptions{CommonName: name, Client: true, ValidFor: validFor})
	if err != nil {
		t.Fatal(err)
	}
	return string(c), string(k)
}

func (e *env) addClient(name string) client {
	e.t.Helper()
	pem, _ := clientCertPEM(e.t, name, time.Hour)
	return decode[client](e.t, e.do("POST", "/clients", map[string]any{"name": name, "certPem": pem}), http.StatusCreated)
}

func (e *env) audits() []auditEntry {
	e.t.Helper()
	list := decode[auditList](e.t, e.do("GET", "/audit-logs", nil), http.StatusOK)
	slices.Reverse(list.Items) // 古い順にする
	return list.Items
}

func TestSubscriberLifecycle(t *testing.T) {
	e := newEnv(t)
	c1, c2 := e.addClient("c1"), e.addClient("c2")
	const imsi = "440100123456789"

	// 登録。状態は必須で、省略した項目には既定値が入る。
	r := e.do("POST", "/subscribers", map[string]any{"imsi": imsi, "ki": strings.ToUpper(testKi), "opc": testOPc, "state": "active", "allowedClientIds": []int64{c2.ID, c1.ID, c1.ID}})
	sub := decode[subscriber](t, r, http.StatusCreated)
	if sub.IMSI != imsi || sub.State != "active" || sub.StateChangedAt.IsZero() || sub.SQN != "000000000000" || sub.AMF != "8000" || sub.SQNType != "inc32" ||
		!slices.Equal(sub.AllowedClientIDs, []int64{c1.ID, c2.ID}) || sub.CreatedAt.IsZero() {
		t.Errorf("created = %+v", sub)
	}
	if loc := r.header.Get("Location"); loc != "/admin/v2/subscribers/"+imsi {
		t.Errorf("Location = %q", loc)
	}
	// 通常の応答には Ki と OPc を含めない。
	if bytes.Contains(bytes.ToLower(r.body), []byte(testKi)) || bytes.Contains(r.body, []byte(testOPc)) {
		t.Errorf("create response leaks keys: %s", r.body)
	}

	wantProblem(t, e.do("POST", "/subscribers", map[string]any{"imsi": imsi, "ki": testKi, "opc": testOPc, "state": "active"}), http.StatusConflict, "SUBSCRIBER_ALREADY_EXISTS")

	r = e.do("GET", "/subscribers/"+imsi, nil)
	if got := decode[subscriber](t, r, http.StatusOK); got.IMSI != imsi || bytes.Contains(r.body, []byte(testKi)) {
		t.Errorf("get = %s", r.body)
	}

	// 鍵は専用の操作でだけ返す。小文字にそろえて返す。
	keys := decode[map[string]string](t, e.do("GET", "/subscribers/"+imsi+"/keys", nil), http.StatusOK)
	if keys["ki"] != testKi || keys["opc"] != testOPc {
		t.Errorf("keys = %v", keys)
	}

	// 変更。指定した項目だけが変わる。
	r = e.do("PATCH", "/subscribers/"+imsi, map[string]any{"sqn": "0000000003E0", "allowedClientIds": []int64{c2.ID}})
	sub = decode[subscriber](t, r, http.StatusOK)
	if sub.SQN != "0000000003e0" || sub.AMF != "8000" || !slices.Equal(sub.AllowedClientIDs, []int64{c2.ID}) {
		t.Errorf("patched = %+v", sub)
	}
	r = e.do("PATCH", "/subscribers/"+imsi, map[string]any{"amf": "9001", "sqnType": "inc33"})
	if sub = decode[subscriber](t, r, http.StatusOK); sub.AMF != "9001" || sub.SQNType != "inc33" || sub.SQN != "0000000003e0" {
		t.Errorf("patched = %+v", sub)
	}

	// 鍵と状態は変更の口では変えられない。不正な変更は何も書き換えない。
	if got := wantProblem(t, e.do("PATCH", "/subscribers/"+imsi, map[string]any{"ki": strings.Repeat("ab", 16), "opc": testOPc, "state": "inactive"}), http.StatusBadRequest, "OPTIONAL_IE_INCORRECT"); !slices.Equal(got, []string{"ki", "opc", "state"}) {
		t.Errorf("invalidParams = %v", got)
	}
	if keys := decode[map[string]string](t, e.do("GET", "/subscribers/"+imsi+"/keys", nil), http.StatusOK); keys["ki"] != testKi {
		t.Errorf("ki changed by a rejected patch: %v", keys)
	}
	if got := wantProblem(t, e.do("PATCH", "/subscribers/"+imsi, map[string]any{"allowedClientIds": []int64{9999}}), http.StatusBadRequest, "CLIENT_NOT_FOUND"); !slices.Equal(got, []string{"allowedClientIds"}) {
		t.Errorf("invalidParams = %v", got)
	}
	if got := wantProblem(t, e.do("PATCH", "/subscribers/"+imsi, `{"amf":null,"sqn":"xyz","bogus":1,"allowPlain":true}`), http.StatusBadRequest, "OPTIONAL_IE_INCORRECT"); !slices.Equal(got, []string{"allowPlain", "amf", "bogus", "sqn"}) {
		t.Errorf("invalidParams = %v", got)
	}
	wantProblem(t, e.do("PATCH", "/subscribers/"+imsi, `{}`), http.StatusBadRequest, "MANDATORY_IE_MISSING")
	wantProblem(t, e.do("PATCH", "/subscribers/"+imsi, `[1]`), http.StatusBadRequest, "INVALID_MSG_FORMAT")
	wantProblem(t, e.do("PATCH", "/subscribers/440100000000000", map[string]any{"amf": "8000"}), http.StatusNotFound, "USER_NOT_FOUND")
	if got := decode[subscriber](t, e.do("GET", "/subscribers/"+imsi, nil), http.StatusOK); got.AMF != "9001" || got.State != "active" {
		t.Errorf("after rejected patches: %+v", got)
	}

	// active は物理削除できない。
	wantProblem(t, e.do("DELETE", "/subscribers/"+imsi, nil), http.StatusConflict, "SUBSCRIBER_ACTIVE")

	// 状態の変更。同じ状態への変更は 200 で何もしない。
	wantProblem(t, e.do("PUT", "/subscribers/"+imsi+"/state", map[string]any{}), http.StatusBadRequest, "MANDATORY_IE_MISSING")
	wantProblem(t, e.do("PUT", "/subscribers/"+imsi+"/state", map[string]any{"state": "suspended"}), http.StatusBadRequest, "MANDATORY_IE_INCORRECT")
	wantProblem(t, e.do("PUT", "/subscribers/"+imsi+"/state", map[string]any{"state": "inactive", "reason": strings.Repeat("あ", 501)}), http.StatusBadRequest, "OPTIONAL_IE_INCORRECT")
	wantProblem(t, e.do("PUT", "/subscribers/440100000000000/state", map[string]any{"state": "inactive"}), http.StatusNotFound, "USER_NOT_FOUND")
	if got := decode[subscriber](t, e.do("PUT", "/subscribers/"+imsi+"/state", map[string]any{"state": "inactive", "reason": "保守"}), http.StatusOK); got.State != "inactive" {
		t.Errorf("after state change: %+v", got)
	}
	if got := decode[subscriber](t, e.do("PUT", "/subscribers/"+imsi+"/state", map[string]any{"state": "inactive"}), http.StatusOK); got.State != "inactive" {
		t.Errorf("after same state: %+v", got)
	}
	if got := decode[subscriber](t, e.do("PUT", "/subscribers/"+imsi+"/state", map[string]any{"state": "terminated"}), http.StatusOK); got.State != "terminated" {
		t.Errorf("after terminate: %+v", got)
	}

	// terminated は変更できず、戻すのは reinstate だけ（理由が必須）。
	wantProblem(t, e.do("PATCH", "/subscribers/"+imsi, map[string]any{"amf": "8000"}), http.StatusConflict, "SUBSCRIBER_TERMINATED")
	wantProblem(t, e.do("PUT", "/subscribers/"+imsi+"/state", map[string]any{"state": "active"}), http.StatusConflict, "STATE_TRANSITION_NOT_ALLOWED")
	if got := wantProblem(t, e.do("POST", "/subscribers/"+imsi+"/reinstate", map[string]any{"reason": " "}), http.StatusBadRequest, "MANDATORY_IE_MISSING"); !slices.Equal(got, []string{"reason"}) {
		t.Errorf("invalidParams = %v", got)
	}
	if got := decode[subscriber](t, e.do("POST", "/subscribers/"+imsi+"/reinstate", map[string]any{"reason": "誤って解約した"}), http.StatusOK); got.State != "inactive" {
		t.Errorf("after reinstate: %+v", got)
	}
	wantProblem(t, e.do("POST", "/subscribers/"+imsi+"/reinstate", map[string]any{"reason": "もう一度"}), http.StatusConflict, "STATE_TRANSITION_NOT_ALLOWED")

	// 削除。
	if r := e.do("DELETE", "/subscribers/"+imsi, nil); r.status != http.StatusNoContent {
		t.Fatalf("delete: status = %d", r.status)
	}
	wantProblem(t, e.do("GET", "/subscribers/"+imsi, nil), http.StatusNotFound, "USER_NOT_FOUND")
	wantProblem(t, e.do("GET", "/subscribers/"+imsi+"/keys", nil), http.StatusNotFound, "USER_NOT_FOUND")
	wantProblem(t, e.do("DELETE", "/subscribers/"+imsi, nil), http.StatusNotFound, "USER_NOT_FOUND")

	// 監査ログ。変更操作と鍵の取得が、操作者つきで順に残る。
	audits := e.audits()
	var actions []string
	for _, a := range audits {
		if a.Operator != "alice" || a.MgmtClient != "test-bff" || a.Time.IsZero() {
			t.Errorf("audit entry = %+v", a)
		}
		actions = append(actions, a.Action)
	}
	want := []string{
		"client.create", "client.create", "subscriber.create",
		"subscriber.keys.read", "subscriber.update", "subscriber.update", "subscriber.keys.read",
		"subscriber.state", "subscriber.state", "subscriber.state", "subscriber.reinstate", "subscriber.delete",
	}
	if !slices.Equal(actions, want) {
		t.Fatalf("audit actions = %v, want %v", actions, want)
	}
	// 登録と削除には、その時点の状態・SQN・AMF・SQN 増加タイプが残る。
	if d := audits[2].Detail; d["state"] != "active" || d["sqn"] != "000000000000" || d["amf"] != "8000" || d["sqnType"] != "inc32" {
		t.Errorf("create detail = %v", d)
	}
	if d := audits[11].Detail; d["state"] != "inactive" || d["sqn"] != "0000000003e0" || d["amf"] != "9001" || d["sqnType"] != "inc33" || audits[11].Target != imsi {
		t.Errorf("delete detail = %v", d)
	}
	// 変更には前後の値が残る。
	if d := fmt.Sprint(audits[4].Detail["sqn"]); !strings.Contains(d, "000000000000") || !strings.Contains(d, "0000000003e0") {
		t.Errorf("update detail sqn = %v", d)
	}
	// 状態の変更には前後の状態と理由が残る。同じ状態への変更には unchanged が付く。
	if d := audits[7].Detail; fmt.Sprint(d["state"]) != "map[from:active to:inactive]" || d["reason"] != "保守" || d["unchanged"] != nil {
		t.Errorf("state detail = %v", d)
	}
	if d := audits[8].Detail; d["unchanged"] != true {
		t.Errorf("unchanged state detail = %v", d)
	}
	if d := audits[10].Detail; fmt.Sprint(d["state"]) != "map[from:terminated to:inactive]" || d["reason"] != "誤って解約した" {
		t.Errorf("reinstate detail = %v", d)
	}
	raw := e.do("GET", "/audit-logs", nil).body
	if bytes.Contains(raw, []byte(testKi)) || bytes.Contains(raw, []byte(testOPc)) {
		t.Errorf("audit log leaks keys: %s", raw)
	}
}

func TestCreateSubscriberValidation(t *testing.T) {
	e := newEnv(t)
	tests := []struct {
		name   string
		body   any
		cause  string
		params []string
	}{
		{"missing required", map[string]any{"sqn": "000000000000"}, "MANDATORY_IE_MISSING", []string{"imsi", "ki", "opc", "state"}},
		{"bad required", map[string]any{"imsi": "12ab", "ki": "00", "opc": testOPc, "state": "terminated"}, "MANDATORY_IE_INCORRECT", []string{"imsi", "ki", "state"}},
		{"bad optional", map[string]any{"imsi": "44010", "ki": testKi, "opc": testOPc, "state": "active", "sqn": "1", "amf": "80000", "sqnType": "inc2", "allowedClientIds": []int64{0}},
			"OPTIONAL_IE_INCORRECT", []string{"allowedClientIds", "amf", "sqn", "sqnType"}},
		{"unknown client", map[string]any{"imsi": "44010", "ki": testKi, "opc": testOPc, "state": "active", "allowedClientIds": []int64{5}}, "CLIENT_NOT_FOUND", []string{"allowedClientIds"}},
		{"unknown member", `{"imsi":"44010","ki":"` + testKi + `","opc":"` + testOPc + `","state":"active","allowPlain":true}`, "INVALID_MSG_FORMAT", nil},
		{"not JSON", `imsi=1`, "INVALID_MSG_FORMAT", nil},
		{"wrong type", `{"imsi":44010}`, "INVALID_MSG_FORMAT", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wantProblem(t, e.do("POST", "/subscribers", tt.body), http.StatusBadRequest, tt.cause); !slices.Equal(got, tt.params) {
				t.Errorf("invalidParams = %v, want %v", got, tt.params)
			}
		})
	}
	// 拒否された登録は何も作らない。
	list := decode[struct {
		Total int `json:"total"`
	}](t, e.do("GET", "/subscribers", nil), http.StatusOK)
	if list.Total != 0 {
		t.Errorf("total = %d after rejected creates", list.Total)
	}
}

func TestListSubscribers(t *testing.T) {
	e := newEnv(t)
	c := e.addClient("c")
	imsis := []string{"440100000000001", "440100000000002", "440100000000003", "440200000000001", "440200000000002"}
	for _, imsi := range imsis {
		decode[subscriber](t, e.do("POST", "/subscribers", map[string]any{"imsi": imsi, "ki": testKi, "opc": testOPc, "state": "active", "allowedClientIds": []int64{c.ID}}), http.StatusCreated)
	}
	type page struct {
		Items      []subscriber `json:"items"`
		Total      int          `json:"total"`
		NextCursor string       `json:"nextCursor"`
	}

	var got []string
	path := "/subscribers?limit=2"
	for {
		r := e.do("GET", path, nil)
		p := decode[page](t, r, http.StatusOK)
		if p.Total != len(imsis) || bytes.Contains(r.body, []byte(testKi)) {
			t.Fatalf("page = %s", r.body)
		}
		for _, s := range p.Items {
			got = append(got, s.IMSI)
		}
		if p.NextCursor == "" {
			break
		}
		path = "/subscribers?limit=2&cursor=" + p.NextCursor
	}
	if !slices.Equal(got, imsis) {
		t.Errorf("listing = %v, want %v", got, imsis)
	}

	p := decode[page](t, e.do("GET", "/subscribers?prefix=4402", nil), http.StatusOK)
	if p.Total != 2 || len(p.Items) != 2 || p.Items[0].IMSI != imsis[3] || p.NextCursor != "" {
		t.Errorf("prefix listing = %+v", p)
	}

	// 一覧が空でも items は配列で返す。
	if r := e.do("GET", "/subscribers?prefix=9", nil); !bytes.Contains(r.body, []byte(`"items":[]`)) {
		t.Errorf("empty listing = %s", r.body)
	}

	for _, q := range []string{"limit=0", "limit=501", "limit=x", "prefix=44a", "cursor=abc"} {
		wantProblem(t, e.do("GET", "/subscribers?"+q, nil), http.StatusBadRequest, "INVALID_QUERY_PARAM")
	}
	if p := decode[page](t, e.do("GET", "/subscribers?limit=500", nil), http.StatusOK); len(p.Items) != len(imsis) {
		t.Errorf("limit=500: %d items", len(p.Items))
	}

	// 削除したクライアントの ID は、後片付けが終わる前でも応答に含めない。
	if r := e.do("DELETE", fmt.Sprintf("/clients/%d", c.ID), nil); r.status != http.StatusNoContent {
		t.Fatalf("delete client: status = %d", r.status)
	}
	p = decode[page](t, e.do("GET", "/subscribers", nil), http.StatusOK)
	for _, s := range p.Items {
		if len(s.AllowedClientIDs) != 0 {
			t.Errorf("subscriber %s still lists the deleted client: %v", s.IMSI, s.AllowedClientIDs)
		}
	}
	// 後片付けは応答の後に行われ、保存されている集合からも消える。
	deadline := time.Now().Add(5 * time.Second)
	for {
		sub, err := e.store.GetSubscriber(t.Context(), imsis[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(sub.AllowedClientIDs) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("deleted client is still in the stored set: %v", sub.AllowedClientIDs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestClientLifecycle(t *testing.T) {
	e := newEnv(t)
	pem, _ := clientCertPEM(t, "radius", time.Hour)

	r := e.do("POST", "/clients", map[string]any{"name": "radius", "certPem": pem})
	c := decode[client](t, r, http.StatusCreated)
	if c.ID != 1 || c.Name != "radius" || !c.Enabled || c.NetworkName != "" || c.Subject != "CN=radius" ||
		len(c.FingerprintSHA256) != 64 || c.NotBefore.IsZero() || !c.NotAfter.After(time.Now()) || c.CertPEM != pem {
		t.Errorf("created = %+v", c)
	}
	if loc := r.header.Get("Location"); loc != "/admin/v2/clients/1" {
		t.Errorf("Location = %q", loc)
	}
	wantProblem(t, e.do("POST", "/clients", map[string]any{"name": "again", "certPem": pem}), http.StatusConflict, "CERT_ALREADY_REGISTERED")

	// 無効な状態で登録することもできる。
	pem2, _ := clientCertPEM(t, "second", time.Hour)
	c2 := decode[client](t, e.do("POST", "/clients", map[string]any{"name": "second", "certPem": pem2, "enabled": false, "networkName": "ETHERNET"}), http.StatusCreated)
	if c2.Enabled || c2.NetworkName != "ETHERNET" || c2.ID <= c.ID {
		t.Errorf("second = %+v", c2)
	}

	list := decode[struct {
		Items []client `json:"items"`
	}](t, e.do("GET", "/clients", nil), http.StatusOK)
	if len(list.Items) != 2 || list.Items[0].ID != c.ID || list.Items[1].ID != c2.ID {
		t.Errorf("list = %+v", list)
	}

	// 入力の検証。
	expired, _ := clientCertPEM(t, "expired", time.Minute) // NotBefore が 5 分前なので期限切れになる
	for _, tt := range []struct {
		body  any
		cause string
	}{
		{map[string]any{"certPem": pem}, "MANDATORY_IE_MISSING"},
		{map[string]any{"name": "x"}, "MANDATORY_IE_MISSING"},
		{map[string]any{"name": "", "certPem": pem}, "MANDATORY_IE_INCORRECT"},
		{map[string]any{"name": "x", "certPem": "not a pem"}, "INVALID_CERTIFICATE"},
		{map[string]any{"name": "x", "certPem": expired}, "INVALID_CERTIFICATE"},
		{map[string]any{"name": "x", "certPem": pem, "networkName": strings.Repeat("n", 256)}, "OPTIONAL_IE_INCORRECT"},
	} {
		wantProblem(t, e.do("POST", "/clients", tt.body), http.StatusBadRequest, tt.cause)
	}

	// 変更。
	path := fmt.Sprintf("/clients/%d", c.ID)
	got := decode[client](t, e.do("PATCH", path, map[string]any{"enabled": false, "networkName": "HRPD"}), http.StatusOK)
	if got.Enabled || got.NetworkName != "HRPD" || got.Name != "radius" || got.FingerprintSHA256 != c.FingerprintSHA256 {
		t.Errorf("patched = %+v", got)
	}
	// Network Name は空文字列で既定値に戻せる。
	if got = decode[client](t, e.do("PATCH", path, map[string]any{"networkName": "", "name": "radius-1"}), http.StatusOK); got.NetworkName != "" || got.Name != "radius-1" {
		t.Errorf("patched = %+v", got)
	}
	if got := wantProblem(t, e.do("PATCH", path, `{"name":"","certPem":"x","enabled":null}`), http.StatusBadRequest, "OPTIONAL_IE_INCORRECT"); !slices.Equal(got, []string{"certPem", "enabled", "name"}) {
		t.Errorf("invalidParams = %v", got)
	}
	wantProblem(t, e.do("PATCH", "/clients/999", map[string]any{"enabled": true}), http.StatusNotFound, "CLIENT_NOT_FOUND")
	wantProblem(t, e.do("GET", "/clients/abc", nil), http.StatusNotFound, "CLIENT_NOT_FOUND")

	// 証明書の差し替え。ID は変わらない。
	renewed, _ := clientCertPEM(t, "radius-renewed", time.Hour)
	got = decode[client](t, e.do("PUT", path+"/certificate", map[string]any{"certPem": renewed}), http.StatusOK)
	if got.ID != c.ID || got.FingerprintSHA256 == c.FingerprintSHA256 || got.Subject != "CN=radius-renewed" || got.CertPEM != renewed || got.Name != "radius-1" {
		t.Errorf("after replace = %+v", got)
	}
	if _, err := e.store.ClientByFingerprint(t.Context(), c.FingerprintSHA256); err == nil {
		t.Error("old certificate still maps to a client")
	}
	wantProblem(t, e.do("PUT", path+"/certificate", map[string]any{"certPem": pem2}), http.StatusConflict, "CERT_ALREADY_REGISTERED")
	wantProblem(t, e.do("PUT", path+"/certificate", map[string]any{"certPem": "junk"}), http.StatusBadRequest, "INVALID_CERTIFICATE")
	wantProblem(t, e.do("PUT", path+"/certificate", map[string]any{}), http.StatusBadRequest, "MANDATORY_IE_MISSING")
	wantProblem(t, e.do("PUT", "/clients/999/certificate", map[string]any{"certPem": renewed}), http.StatusNotFound, "CLIENT_NOT_FOUND")
	// 古い証明書は、差し替え後に別のクライアントとして登録できる。
	decode[client](t, e.do("POST", "/clients", map[string]any{"name": "reuse-old-cert", "certPem": pem}), http.StatusCreated)

	// 削除。
	if r := e.do("DELETE", path, nil); r.status != http.StatusNoContent {
		t.Fatalf("delete: status = %d", r.status)
	}
	wantProblem(t, e.do("GET", path, nil), http.StatusNotFound, "CLIENT_NOT_FOUND")
	wantProblem(t, e.do("DELETE", path, nil), http.StatusNotFound, "CLIENT_NOT_FOUND")

	var actions []string
	for _, a := range e.audits() {
		actions = append(actions, a.Action)
	}
	want := []string{"client.create", "client.create", "client.update", "client.update", "client.certificate.replace", "client.create", "client.delete"}
	if !slices.Equal(actions, want) {
		t.Errorf("audit actions = %v, want %v", actions, want)
	}
}

type serverCert struct {
	CertPEM           string    `json:"certPem"`
	Source            string    `json:"source"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	Subject           string    `json:"subject"`
	NotAfter          time.Time `json:"notAfter"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

func TestAVServerCertificate(t *testing.T) {
	e := newEnv(t)

	r := e.do("GET", "/av-server-certificate", nil)
	initial := decode[serverCert](t, r, http.StatusOK)
	if initial.Source != "self-signed" || initial.Subject != "CN=aka-vecgen" || len(initial.FingerprintSHA256) != 64 {
		t.Errorf("initial = %+v", initial)
	}
	if bytes.Contains(r.body, []byte("PRIVATE KEY")) {
		t.Errorf("response contains the private key: %s", r.body)
	}

	// 持ち込みの証明書に差し替える。
	certPEM, keyPEM, err := certs.SelfSigned(certs.SelfSignedOptions{CommonName: "aka.example.net", Hosts: []string{"aka.example.net"}, ValidFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	r = e.do("PUT", "/av-server-certificate", map[string]any{"certPem": string(certPEM), "keyPem": string(keyPEM)})
	uploaded := decode[serverCert](t, r, http.StatusOK)
	if uploaded.Source != "uploaded" || uploaded.Subject != "CN=aka.example.net" || uploaded.FingerprintSHA256 == initial.FingerprintSHA256 {
		t.Errorf("uploaded = %+v", uploaded)
	}
	if bytes.Contains(r.body, []byte("PRIVATE KEY")) {
		t.Errorf("response contains the private key: %s", r.body)
	}
	if got := decode[serverCert](t, e.do("GET", "/av-server-certificate", nil), http.StatusOK); got.FingerprintSHA256 != uploaded.FingerprintSHA256 {
		t.Errorf("get after put = %+v", got)
	}

	// 不正な入力では差し替えない。
	_, otherKey, _ := certs.SelfSigned(certs.SelfSignedOptions{CommonName: "other", ValidFor: time.Hour})
	expiredCert, expiredKey, _ := certs.SelfSigned(certs.SelfSignedOptions{CommonName: "expired", ValidFor: time.Minute})
	for _, tt := range []struct {
		body  any
		cause string
	}{
		{map[string]any{"certPem": string(certPEM)}, "MANDATORY_IE_MISSING"},
		{map[string]any{"certPem": string(certPEM), "keyPem": string(otherKey)}, "INVALID_CERTIFICATE"},
		{map[string]any{"certPem": "junk", "keyPem": string(keyPEM)}, "INVALID_CERTIFICATE"},
		{map[string]any{"certPem": string(expiredCert), "keyPem": string(expiredKey)}, "INVALID_CERTIFICATE"},
	} {
		wantProblem(t, e.do("PUT", "/av-server-certificate", tt.body), http.StatusBadRequest, tt.cause)
	}
	if got := decode[serverCert](t, e.do("GET", "/av-server-certificate", nil), http.StatusOK); got.FingerprintSHA256 != uploaded.FingerprintSHA256 {
		t.Errorf("certificate changed by a rejected put: %+v", got)
	}

	// 削除すると自己署名を再生成する。証明書のない状態にはならない。
	reset := decode[serverCert](t, e.do("DELETE", "/av-server-certificate", nil), http.StatusOK)
	if reset.Source != "self-signed" || reset.FingerprintSHA256 == uploaded.FingerprintSHA256 || reset.FingerprintSHA256 == initial.FingerprintSHA256 {
		t.Errorf("reset = %+v", reset)
	}

	status := decode[struct {
		NotAfter time.Time `json:"avServerCertificateNotAfter"`
	}](t, e.do("GET", "/status", nil), http.StatusOK)
	if !status.NotAfter.Equal(reset.NotAfter) {
		t.Errorf("status notAfter = %v, want %v", status.NotAfter, reset.NotAfter)
	}

	audits := e.audits()
	if len(audits) != 2 || audits[0].Action != "av-server-certificate.replace" || audits[1].Action != "av-server-certificate.reset" {
		t.Errorf("audits = %+v", audits)
	}
}

func TestStatus(t *testing.T) {
	e := newEnv(t)
	e.addClient("c")
	decode[subscriber](t, e.do("POST", "/subscribers", map[string]any{"imsi": "44010", "ki": testKi, "opc": testOPc, "state": "active"}), http.StatusCreated)

	s := decode[struct {
		Version         string    `json:"version"`
		BootID          string    `json:"bootId"`
		StartedAt       time.Time `json:"startedAt"`
		SubscriberCount int       `json:"subscriberCount"`
		ClientCount     int       `json:"clientCount"`
	}](t, e.do("GET", "/status", nil), http.StatusOK)
	if s.Version != "test" || s.BootID != "boot-1" || s.StartedAt.IsZero() || s.SubscriberCount != 1 || s.ClientCount != 1 {
		t.Errorf("status = %+v", s)
	}
}

func TestLogs(t *testing.T) {
	e := newEnv(t)
	type logList struct {
		BootID string `json:"bootId"`
		Items  []struct {
			Seq   int64          `json:"seq"`
			Level string         `json:"level"`
			Msg   string         `json:"msg"`
			Attrs map[string]any `json:"attrs"`
		} `json:"items"`
		LastSeq int64 `json:"lastSeq"`
	}

	e.log.Warn("first marker", "imsi", "44010")
	all := decode[logList](t, e.do("GET", "/logs", nil), http.StatusOK)
	if all.BootID != "boot-1" || len(all.Items) == 0 {
		t.Fatalf("logs = %+v", all)
	}
	last := all.Items[len(all.Items)-1]
	if last.Msg != "first marker" || last.Level != "WARN" || last.Attrs["imsi"] != "44010" || all.LastSeq != last.Seq {
		t.Errorf("last entry = %+v, lastSeq = %d", last, all.LastSeq)
	}

	// after を指定すると、それより後のログだけを返す。
	none := decode[logList](t, e.do("GET", fmt.Sprintf("/logs?after=%d", all.LastSeq), nil), http.StatusOK)
	if len(none.Items) != 0 || none.LastSeq != all.LastSeq {
		t.Errorf("nothing new: %+v", none)
	}
	e.log.Info("second marker")
	e.log.Info("third marker")
	next := decode[logList](t, e.do("GET", fmt.Sprintf("/logs?after=%d&limit=1", all.LastSeq), nil), http.StatusOK)
	if len(next.Items) != 1 || next.Items[0].Msg != "second marker" || next.LastSeq != all.LastSeq+1 {
		t.Errorf("next = %+v", next)
	}
	if latest := decode[logList](t, e.do("GET", "/logs?limit=1", nil), http.StatusOK); len(latest.Items) != 1 || latest.Items[0].Msg != "third marker" {
		t.Errorf("latest = %+v", latest)
	}

	for _, q := range []string{"after=-1", "after=x", "limit=0", "limit=1001"} {
		wantProblem(t, e.do("GET", "/logs?"+q, nil), http.StatusBadRequest, "INVALID_QUERY_PARAM")
	}
}

func TestAuditLogPaging(t *testing.T) {
	e := newEnv(t)
	for i := range 5 {
		e.addClient(fmt.Sprintf("c%d", i))
	}
	var targets []string
	path := "/audit-logs?limit=2"
	for {
		list := decode[auditList](t, e.do("GET", path, nil), http.StatusOK)
		for _, a := range list.Items {
			targets = append(targets, a.Target)
		}
		if list.NextBefore == "" {
			break
		}
		path = "/audit-logs?limit=2&before=" + list.NextBefore
	}
	if want := []string{"5", "4", "3", "2", "1"}; !slices.Equal(targets, want) {
		t.Errorf("targets = %v, want %v", targets, want)
	}
	for _, q := range []string{"before=abc", "limit=0", "limit=501"} {
		wantProblem(t, e.do("GET", "/audit-logs?"+q, nil), http.StatusBadRequest, "INVALID_QUERY_PARAM")
	}
}

func TestOperatorHeader(t *testing.T) {
	e := newEnv(t)
	send := func(operator string) response {
		req := httptest.NewRequest("POST", "/admin/v2/clients", strings.NewReader(`{"name":"c","certPem":"`+strings.ReplaceAll(must(clientCertPEM(t, "c"+operator, time.Hour)), "\n", `\n`)+`"}`))
		if operator != "" {
			req.Header.Set("X-Operator-Id", operator)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return response{rec.Code, rec.Header(), rec.Body.Bytes()}
	}

	// 形式が不正なら拒否する。
	if got := wantProblem(t, send("bad operator!"), http.StatusBadRequest, "OPTIONAL_IE_INCORRECT"); !slices.Equal(got, []string{"X-Operator-Id"}) {
		t.Errorf("invalidParams = %v", got)
	}
	// 省略した場合は、管理クライアントの識別名だけが残る。
	if r := send(""); r.status != http.StatusCreated {
		t.Fatalf("no operator: status = %d (%s)", r.status, r.body)
	}
	audits := e.audits()
	if len(audits) != 1 || audits[0].Operator != "" || audits[0].MgmtClient != "test-bff" {
		t.Errorf("audits = %+v", audits)
	}
}

func TestTraceID(t *testing.T) {
	e := newEnv(t)
	send := func(method, path, operator, traceID string, body string) response {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, "/admin/v2"+path, rd)
		if operator != "" {
			req.Header.Set("X-Operator-Id", operator)
		}
		if traceID != "" {
			req.Header.Set("X-Trace-ID", traceID)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return response{rec.Code, rec.Header(), rec.Body.Bytes()}
	}
	subscriber := func(imsi string) string {
		return `{"imsi":"` + imsi + `","ki":"` + testKi + `","opc":"` + testOPc + `","state":"active"}`
	}
	generated := regexp.MustCompile(`^[0-9a-f]{32}$`)

	// 受け取ったトレースID を応答で返し、監査ログに残す。
	if r := send("POST", "/subscribers", "alice", "trace-001", subscriber("001010000000001")); r.status != http.StatusCreated || r.header.Get("X-Trace-ID") != "trace-001" {
		t.Fatalf("given: status = %d, X-Trace-ID = %q (%s)", r.status, r.header.Get("X-Trace-ID"), r.body)
	}
	// ないとき、形式が違うとき（空白を含む、65 文字）は採番する。
	var issued []string
	for i, v := range []string{"", "bad trace", strings.Repeat("a", 65)} {
		r := send("POST", "/subscribers", "alice", v, subscriber(fmt.Sprintf("00101000000001%d", i)))
		got := r.header.Get("X-Trace-ID")
		if r.status != http.StatusCreated || !generated.MatchString(got) {
			t.Fatalf("trace %q: status = %d, X-Trace-ID = %q", v, r.status, got)
		}
		issued = append(issued, got)
	}
	// エラーの応答にも付ける。
	if r := send("GET", "/subscribers/001010000000099", "", "trace-404", ""); r.status != http.StatusNotFound || r.header.Get("X-Trace-ID") != "trace-404" {
		t.Errorf("error response: status = %d, X-Trace-ID = %q", r.status, r.header.Get("X-Trace-ID"))
	}
	if r := send("GET", "/status", "bad operator!", "trace-400", ""); r.status != http.StatusBadRequest || r.header.Get("X-Trace-ID") != "trace-400" {
		t.Errorf("bad operator: status = %d, X-Trace-ID = %q", r.status, r.header.Get("X-Trace-ID"))
	}

	var traces []string
	for _, a := range e.audits() {
		traces = append(traces, a.TraceID)
	}
	if want := append([]string{"trace-001"}, issued...); !slices.Equal(traces, want) {
		t.Errorf("audit traceIds = %v, want %v", traces, want)
	}

	// 処理を終えたリクエストを admin request completed として記録する。GET /logs は info では記録しない。
	type logList struct {
		Items []struct {
			Level string         `json:"level"`
			Msg   string         `json:"msg"`
			Attrs map[string]any `json:"attrs"`
		} `json:"items"`
	}
	completed := map[string]map[string]any{}
	for _, l := range decode[logList](t, e.do("GET", "/logs", nil), http.StatusOK).Items {
		if l.Msg != "admin request completed" {
			continue
		}
		if l.Level != "INFO" {
			t.Errorf("level = %s", l.Level)
		}
		if l.Attrs["path"] == "/admin/v2/logs" {
			t.Errorf("GET /logs is logged at info: %v", l.Attrs)
		}
		completed[fmt.Sprint(l.Attrs["trace_id"])] = l.Attrs
	}
	if a := completed["trace-001"]; a == nil || a["method"] != "POST" || a["path"] != "/admin/v2/subscribers" ||
		fmt.Sprint(a["http_status"]) != "201" || a["mgmt_client"] != "test-bff" || a["operator"] != "alice" {
		t.Errorf("trace-001 = %v", a)
	}
	if a := completed["trace-404"]; a == nil || fmt.Sprint(a["http_status"]) != "404" || a["operator"] != "" {
		t.Errorf("trace-404 = %v", a)
	}
	// 形式の違う操作者 ID はそのまま記録しない。
	if a := completed["trace-400"]; a == nil || fmt.Sprint(a["http_status"]) != "400" || a["operator"] != "" {
		t.Errorf("trace-400 = %v", a)
	}
}

// must は 2 値を返す関数の 1 つ目を取り出す。
func must(a, _ string) string { return a }
