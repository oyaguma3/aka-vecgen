package adminapi

import (
	"encoding/json/jsontext"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/logbuf"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

// ---- 状態 ----

type statusJSON struct {
	Version                     string    `json:"version"`
	BootID                      string    `json:"bootId"`
	StartedAt                   time.Time `json:"startedAt"`
	SubscriberCount             int64     `json:"subscriberCount"`
	ClientCount                 int64     `json:"clientCount"`
	AVServerCertificateNotAfter time.Time `json:"avServerCertificateNotAfter"`
}

func (h *Handler) getStatus(w http.ResponseWriter, r *http.Request) {
	subs, err := h.Store.CountSubscribers(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	clients, err := h.Store.CountClients(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	sc, err := h.Certs.AVCertificate(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	cert, err := certs.ParsePEM(sc.CertPEM)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, statusJSON{
		Version:                     h.Version,
		BootID:                      h.BootID,
		StartedAt:                   h.StartedAt,
		SubscriberCount:             subs,
		ClientCount:                 clients,
		AVServerCertificateNotAfter: cert.NotAfter.UTC(),
	})
}

// ---- AV 用サーバー証明書 ----

type serverCertificateJSON struct {
	CertPEM           string    `json:"certPem"`
	Source            string    `json:"source"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	Subject           string    `json:"subject"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type serverCertificateReplaceJSON struct {
	CertPEM *string `json:"certPem"`
	KeyPEM  *string `json:"keyPem"`
}

// writeServerCertificate はサーバー証明書の情報を書き込む。秘密鍵は返さない。
func (h *Handler) writeServerCertificate(w http.ResponseWriter, r *http.Request, sc store.ServerCertificate) {
	cert, err := certs.ParsePEM(sc.CertPEM)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, serverCertificateJSON{
		CertPEM:           string(sc.CertPEM),
		Source:            sc.Source,
		FingerprintSHA256: certs.Fingerprint(cert),
		Subject:           cert.Subject.String(),
		NotBefore:         cert.NotBefore.UTC(),
		NotAfter:          cert.NotAfter.UTC(),
		UpdatedAt:         sc.UpdatedAt,
	})
}

func (h *Handler) getAVServerCertificate(w http.ResponseWriter, r *http.Request) {
	sc, err := h.Certs.AVCertificate(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	h.writeServerCertificate(w, r, sc)
}

// certFingerprint は PEM の証明書のフィンガープリントを返す。解析できなければ空文字列を返す。
func certFingerprint(pem []byte) string {
	cert, err := certs.ParsePEM(pem)
	if err != nil {
		return ""
	}
	return certs.Fingerprint(cert)
}

func (h *Handler) replaceAVServerCertificate(w http.ResponseWriter, r *http.Request) {
	var body serverCertificateReplaceJSON
	if p := decodeBody(w, r, &body); p != nil {
		p.write(w)
		return
	}
	var v validation
	if body.CertPEM == nil {
		v.missing = append(v.missing, invalidParam{"certPem", "is required"})
	}
	if body.KeyPEM == nil {
		v.missing = append(v.missing, invalidParam{"keyPem", "is required"})
	}
	if p := v.problem(); p != nil {
		p.write(w)
		return
	}

	before, err := h.Certs.AVCertificate(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	sc, err := h.Certs.ReplaceAVCertificate(r.Context(), []byte(*body.CertPEM), []byte(*body.KeyPEM))
	if errors.Is(err, certs.ErrInvalid) {
		newProblem(http.StatusBadRequest, causeInvalidCertificate, err.Error()).write(w)
		return
	}
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	h.audit(r, "av-server-certificate.replace", "av-server-certificate", map[string]any{
		"fingerprintSha256": change{certFingerprint(before.CertPEM), certFingerprint(sc.CertPEM)},
	})
	h.writeServerCertificate(w, r, sc)
}

func (h *Handler) resetAVServerCertificate(w http.ResponseWriter, r *http.Request) {
	before, err := h.Certs.AVCertificate(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	sc, err := h.Certs.ResetAVCertificate(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	h.audit(r, "av-server-certificate.reset", "av-server-certificate", map[string]any{
		"fingerprintSha256": change{certFingerprint(before.CertPEM), certFingerprint(sc.CertPEM)},
	})
	h.writeServerCertificate(w, r, sc)
}

// ---- ログ ----

type logEntryJSON struct {
	Seq   int64          `json:"seq"`
	Time  time.Time      `json:"time"`
	Level string         `json:"level"`
	Msg   string         `json:"msg"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

type logListJSON struct {
	BootID  string         `json:"bootId"`
	Items   []logEntryJSON `json:"items"`
	LastSeq int64          `json:"lastSeq"`
}

func (h *Handler) listLogs(w http.ResponseWriter, r *http.Request) {
	limit, p := queryInt(r, "limit", 200, 1, 1000)
	if p != nil {
		p.write(w)
		return
	}
	var entries []logbuf.Entry
	out := logListJSON{BootID: h.BootID}
	if r.URL.Query().Has("after") {
		after, p := queryInt(r, "after", 0, 0, 1<<62)
		if p != nil {
			p.write(w)
			return
		}
		entries = h.Logs.After(after, int(limit))
		out.LastSeq = after
	} else {
		entries = h.Logs.Latest(int(limit))
	}

	out.Items = make([]logEntryJSON, len(entries))
	for i, e := range entries {
		out.Items[i] = logEntryJSON{Seq: e.Seq, Time: e.Time, Level: e.Level, Msg: e.Msg, Attrs: e.Attrs}
		out.LastSeq = e.Seq
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- 監査ログ ----

type auditLogEntryJSON struct {
	ID         string         `json:"id"`
	Time       time.Time      `json:"time"`
	Operator   string         `json:"operator"`
	MgmtClient string         `json:"mgmtClient"`
	Action     string         `json:"action"`
	Target     string         `json:"target"`
	TraceID    string         `json:"traceId"`
	Detail     jsontext.Value `json:"detail,omitempty"`
}

type auditLogListJSON struct {
	Items      []auditLogEntryJSON `json:"items"`
	NextBefore string              `json:"nextBefore,omitempty"`
}

var auditIDPattern = regexp.MustCompile(`^[0-9]+-[0-9]+$`)

func (h *Handler) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	before := r.URL.Query().Get("before")
	if before != "" && !auditIDPattern.MatchString(before) {
		badParams(causeInvalidQueryParam, invalidParam{"before", "must be a nextBefore value from a previous response"}).write(w)
		return
	}
	limit, p := queryInt(r, "limit", 100, 1, 500)
	if p != nil {
		p.write(w)
		return
	}

	entries, next, err := h.Store.ListAudit(r.Context(), before, int(limit))
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	out := auditLogListJSON{Items: make([]auditLogEntryJSON, len(entries)), NextBefore: next}
	for i, e := range entries {
		out.Items[i] = auditLogEntryJSON{
			ID: e.ID, Time: e.Time, Operator: e.Operator, MgmtClient: e.MgmtClient, Action: e.Action, Target: e.Target,
			TraceID: e.TraceID,
		}
		// 保存してある JSON をそのまま埋め込む。壊れている場合は省く。
		if v := jsontext.Value(e.Detail); e.Detail != "" && v.IsValid() {
			out.Items[i].Detail = v
		}
	}
	writeJSON(w, http.StatusOK, out)
}
