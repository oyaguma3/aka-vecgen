// Package adminapi は管理API を提供する。
// API 仕様は docs/openapi/admin-api.yaml を参照。
package adminapi

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/audit"
	"github.com/oyaguma3/aka-vecgen/internal/store"
	"github.com/oyaguma3/aka-vecgen/internal/traceid"
)

const maxBodyBytes = 256 << 10

// Store は管理API が使うデータ操作。
type Store interface {
	CreateSubscriber(ctx context.Context, sub store.Subscriber) error
	GetSubscriber(ctx context.Context, imsi string) (store.Subscriber, error)
	SubscriberKeys(ctx context.Context, imsi string) (ki, opc []byte, err error)
	KEKID() string
	UpdateSubscriber(ctx context.Context, imsi string, p store.SubscriberPatch) error
	DeleteSubscriber(ctx context.Context, imsi string) error
	SetState(ctx context.Context, imsi string, to store.State) (from store.State, unchanged bool, err error)
	Reinstate(ctx context.Context, imsi string) (store.State, error)
	ListSubscribers(ctx context.Context, prefix, cursor string, limit int) (store.SubscriberPage, error)
	GetSubscribers(ctx context.Context, imsis []string) ([]store.Subscriber, error)
	CountSubscribers(ctx context.Context) (int64, error)

	GetClient(ctx context.Context, id int64) (store.Client, error)
	ListClients(ctx context.Context) ([]store.Client, error)
	ClientIDs(ctx context.Context) ([]int64, error)
	CountClients(ctx context.Context) (int64, error)

	ListAudit(ctx context.Context, before string, limit int) ([]store.AuditEntry, string, error)
}

// Server は、動いているサーバーの状態（証明書と管理クライアント）を返す。
// AV クライアントとサーバー証明書の書き込みはノードの上のコマンドで行い、管理API は読み出しだけにする（設計概要 §9.3）。
type Server interface {
	AVCertificate(ctx context.Context) (store.ServerCertificate, error)
	CertificateNotAfter() (av, admin time.Time)
	AdminClients() (names []string, loadedAt time.Time)
}

// Handler は管理API のハンドラー。
type Handler struct {
	Store  Store
	Server Server
	Audit  *audit.Recorder
	Log    *slog.Logger
	// MgmtClient はリクエストから管理クライアントの識別名を取り出す。
	MgmtClient func(*http.Request) string
	// KeyExport は鍵の読み出しの口を有効にするか（VECGEN_KEY_EXPORT。設計概要 §8.4）。
	KeyExport bool

	Version   string
	BootID    string
	StartedAt time.Time
}

// Routes は管理API のルーティングを返す。
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v2/status", h.getStatus)

	mux.HandleFunc("GET /admin/v2/subscribers", h.listSubscribers)
	mux.HandleFunc("POST /admin/v2/subscribers", h.createSubscriber)
	mux.HandleFunc("POST /admin/v2/subscribers/batch-get", h.batchGetSubscribers)
	mux.HandleFunc("GET /admin/v2/subscribers/{imsi}", h.getSubscriber)
	mux.HandleFunc("PATCH /admin/v2/subscribers/{imsi}", h.updateSubscriber)
	mux.HandleFunc("DELETE /admin/v2/subscribers/{imsi}", h.deleteSubscriber)
	mux.HandleFunc("PUT /admin/v2/subscribers/{imsi}/state", h.setSubscriberState)
	mux.HandleFunc("POST /admin/v2/subscribers/{imsi}/reinstate", h.reinstateSubscriber)
	mux.HandleFunc("GET /admin/v2/subscribers/{imsi}/keys", h.getSubscriberKeys)

	// AV クライアントとサーバー証明書は読み出しだけ（書き込みはノードの上のコマンド。設計概要 §9.3）
	mux.HandleFunc("GET /admin/v2/clients", h.listClients)
	mux.HandleFunc("GET /admin/v2/clients/{clientId}", h.getClient)
	mux.HandleFunc("GET /admin/v2/av-server-certificate", h.getAVServerCertificate)

	mux.HandleFunc("GET /admin/v2/audit-logs", h.listAuditLogs)
	return h.observe(checkOperator(mux))
}

type traceIDKey struct{}

// traceID はリクエストのトレースID を返す。
func traceID(r *http.Request) string {
	id, _ := r.Context().Value(traceIDKey{}).(string)
	return id
}

// observe は X-Trace-ID ヘッダーのトレースID を使い（なければ採番し）、応答の X-Trace-ID ヘッダーで返す。
// 処理を終えたリクエストは admin request completed（ADMIN_REQUEST）として記録する。
func (h *Handler) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := traceid.Resolve(r.Header.Get(traceid.Header))
		w.Header().Set(traceid.Header, id)
		r = r.WithContext(context.WithValue(r.Context(), traceIDKey{}, id))
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		operator := r.Header.Get(operatorHeader)
		if !operatorPattern.MatchString(operator) {
			operator = "" // 形式の違う値は 400 で断っており、そのままは記録しない
		}
		srcIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			srcIP = r.RemoteAddr
		}
		h.Log.Info("admin request completed",
			"event_id", "ADMIN_REQUEST",
			"trace_id", id,
			"method", r.Method,
			"path", r.URL.Path,
			"http_status", rec.status,
			"latency_ms", time.Since(start).Milliseconds(),
			"mgmt_client", h.MgmtClient(r),
			"operator", operator,
			"src_ip", srcIP,
		)
	})
}

// statusRecorder は応答のステータスを記録する。
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap は http.ResponseController が元の ResponseWriter を使えるようにする。
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

const operatorHeader = "X-Operator-Id"

var operatorPattern = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// checkOperator は X-Operator-Id ヘッダーの形式を確認する。ヘッダーは省略できる。
func checkOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get(operatorHeader); v != "" && !operatorPattern.MatchString(v) {
			badParams(causeOptionalIEIncorrect, invalidParam{operatorHeader, "must match " + operatorPattern.String()}).write(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- エラー応答 ----

// ProblemDetails の cause の値。
const (
	causeInvalidMsgFormat     = "INVALID_MSG_FORMAT"
	causeInvalidQueryParam    = "INVALID_QUERY_PARAM"
	causeMandatoryIEMissing   = "MANDATORY_IE_MISSING"
	causeMandatoryIEIncorrect = "MANDATORY_IE_INCORRECT"
	causeOptionalIEIncorrect  = "OPTIONAL_IE_INCORRECT"
	causeUserNotFound         = "USER_NOT_FOUND"
	causeSubscriberExists     = "SUBSCRIBER_ALREADY_EXISTS"
	causeSubscriberActive     = "SUBSCRIBER_ACTIVE"
	causeSubscriberTerminated = "SUBSCRIBER_TERMINATED"
	causeTransitionNotAllowed = "STATE_TRANSITION_NOT_ALLOWED"
	causeClientNotFound       = "CLIENT_NOT_FOUND"
	causeKeyExportDisabled    = "KEY_EXPORT_DISABLED"
	causeSystemFailure        = "SYSTEM_FAILURE"
)

type invalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason,omitempty"`
}

type problem struct {
	Title         string         `json:"title"`
	Status        int            `json:"status"`
	Detail        string         `json:"detail,omitempty"`
	Cause         string         `json:"cause"`
	InvalidParams []invalidParam `json:"invalidParams,omitempty"`
}

func newProblem(status int, cause, detail string) *problem {
	return &problem{Title: http.StatusText(status), Status: status, Cause: cause, Detail: detail}
}

func badParams(cause string, params ...invalidParam) *problem {
	p := newProblem(http.StatusBadRequest, cause, "")
	p.InvalidParams = params
	return p
}

func (p *problem) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	json.MarshalWrite(w, p)
}

// internalError は内部エラーを記録し、詳細を伏せた 500 を返す。
func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("admin request failed", "event_id", "ADMIN_ERROR", "trace_id", traceID(r), "method", r.Method, "path", r.URL.Path, "error", err)
	newProblem(http.StatusInternalServerError, causeSystemFailure, "").write(w)
}

// validation は入力検証の結果を集める。
type validation struct {
	missing   []invalidParam // 必須項目がない
	mandatory []invalidParam // 必須項目の値が不正
	optional  []invalidParam // 任意項目の値が不正
}

// problem は検証エラーがあれば 400 を返す。なければ nil。
// cause は、必須項目の欠落、必須項目の不正、任意項目の不正の順に優先する。
func (v *validation) problem() *problem {
	all := append(append(append([]invalidParam(nil), v.missing...), v.mandatory...), v.optional...)
	switch {
	case len(v.missing) > 0:
		return badParams(causeMandatoryIEMissing, all...)
	case len(v.mandatory) > 0:
		return badParams(causeMandatoryIEIncorrect, all...)
	case len(v.optional) > 0:
		return badParams(causeOptionalIEIncorrect, all...)
	}
	return nil
}

// ---- 入出力 ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.MarshalWrite(w, v)
}

// decodeBody はリクエストボディを v に読み込む。未知の項目は拒否する。
func decodeBody(w http.ResponseWriter, r *http.Request, v any) *problem {
	err := json.UnmarshalRead(http.MaxBytesReader(w, r.Body, maxBodyBytes), v, json.RejectUnknownMembers(true))
	if err != nil {
		return newProblem(http.StatusBadRequest, causeInvalidMsgFormat, "request body is not valid JSON for this operation")
	}
	return nil
}

// decodePatch は JSON Merge Patch のボディを項目ごとの生の値として読み込む。
// 空のオブジェクトと null の値は拒否する。
func decodePatch(w http.ResponseWriter, r *http.Request) (map[string]jsontext.Value, *problem) {
	var fields map[string]jsontext.Value
	if err := json.UnmarshalRead(http.MaxBytesReader(w, r.Body, maxBodyBytes), &fields); err != nil {
		return nil, newProblem(http.StatusBadRequest, causeInvalidMsgFormat, "request body must be a JSON object")
	}
	if len(fields) == 0 {
		return nil, newProblem(http.StatusBadRequest, causeMandatoryIEMissing, "at least one field is required")
	}
	return fields, nil
}

// patchField は patch の項目 name を T として読む。項目がなければ nil を返す。
// 値が null または T として読めない場合は v に記録する。
func patchField[T any](fields map[string]jsontext.Value, name string, v *validation) *T {
	raw, ok := fields[name]
	if !ok {
		return nil
	}
	delete(fields, name)
	if raw.Kind() == 'n' {
		v.optional = append(v.optional, invalidParam{name, "must not be null"})
		return nil
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		v.optional = append(v.optional, invalidParam{name, "has a wrong type"})
		return nil
	}
	return &out
}

// rejectUnknown は、patchField で読まれずに残った項目を未知の項目として記録する。
func rejectUnknown(fields map[string]jsontext.Value, v *validation) {
	for name := range fields {
		v.optional = append(v.optional, invalidParam{name, "unknown field"})
	}
}

// queryInt はクエリパラメーター name を整数として読む。省略時は def を返す。
func queryInt(r *http.Request, name string, def, lo, hi int64) (int64, *problem) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < lo || n > hi {
		reason := "must be an integer between " + strconv.FormatInt(lo, 10) + " and " + strconv.FormatInt(hi, 10)
		return 0, badParams(causeInvalidQueryParam, invalidParam{name, reason})
	}
	return n, nil
}

// ---- 監査ログ ----

// audit は操作を監査ログに記録する。detail は変更内容で、nil なら記録しない。
// 記録に失敗しても操作自体は成功として扱い、エラーをログに残す。
func (h *Handler) audit(r *http.Request, action, target string, detail any) {
	e := store.AuditEntry{
		Operator:   r.Header.Get(operatorHeader),
		MgmtClient: h.MgmtClient(r),
		Action:     action,
		Target:     target,
		TraceID:    traceID(r),
	}
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			h.Log.Error("marshal audit detail", "event_id", "AUDIT_WRITE_ERR", "trace_id", e.TraceID, "action", action, "error", err)
		}
		e.Detail = string(b)
	}
	h.Audit.Record(r.Context(), e)
}
