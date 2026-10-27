package adminapi

import (
	"encoding/json/jsontext"
	"net/http"
	"regexp"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

// ---- 状態 ----

type statusJSON struct {
	Version   string    `json:"version"`
	BootID    string    `json:"bootId"`
	StartedAt time.Time `json:"startedAt"`
	// AVAPIContractVersion は、合わせている認証ベクターAPI の契約の版（aka-mvpset の docs/av-api-contract.md §13）。
	AVAPIContractVersion           string    `json:"avApiContractVersion"`
	SubscriberCount                int64     `json:"subscriberCount"`
	ClientCount                    int64     `json:"clientCount"`
	AVServerCertificateNotAfter    time.Time `json:"avServerCertificateNotAfter"`
	AdminServerCertificateNotAfter time.Time `json:"adminServerCertificateNotAfter"`
	// KEKID は使っている KEK の識別子（SHA-256 の先頭 8 バイトの 16 進。設計概要 §8.1）。
	KEKID string `json:"kekId"`
	// AdminClients は管理クライアントの識別名、AdminClientsLoadedAt はピンのファイルを読み込んだ日時（SIGHUP で読み直す）。
	AdminClients         []string  `json:"adminClients"`
	AdminClientsLoadedAt time.Time `json:"adminClientsLoadedAt"`
}

// AVAPIContractVersion は、合わせている認証ベクターAPI の契約の版。
const AVAPIContractVersion = "1.0.0"

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
	avNotAfter, adminNotAfter := h.Server.CertificateNotAfter()
	names, loadedAt := h.Server.AdminClients()
	if names == nil {
		names = []string{}
	}
	writeJSON(w, http.StatusOK, statusJSON{
		Version:                        h.Version,
		BootID:                         h.BootID,
		StartedAt:                      h.StartedAt,
		AVAPIContractVersion:           AVAPIContractVersion,
		SubscriberCount:                subs,
		ClientCount:                    clients,
		AVServerCertificateNotAfter:    avNotAfter.UTC(),
		AdminServerCertificateNotAfter: adminNotAfter.UTC(),
		KEKID:                          h.Store.KEKID(),
		AdminClients:                   names,
		AdminClientsLoadedAt:           loadedAt,
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
	sc, err := h.Server.AVCertificate(r.Context())
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
