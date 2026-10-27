package adminapi

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

const (
	maxClientNameLen  = 64
	maxNetworkNameLen = 255
	// purgeTimeout は、削除したクライアントを各加入者の許可クライアントから取り除く処理の上限時間。
	purgeTimeout = 5 * time.Minute
)

type clientJSON struct {
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

type clientListJSON struct {
	Items []clientJSON `json:"items"`
}

type clientCreateJSON struct {
	Name        *string `json:"name"`
	CertPEM     *string `json:"certPem"`
	Enabled     *bool   `json:"enabled"`
	NetworkName *string `json:"networkName"`
}

type clientCertificateJSON struct {
	CertPEM *string `json:"certPem"`
}

func toClientJSON(c store.Client) clientJSON {
	out := clientJSON{
		ID:                c.ID,
		Name:              c.Name,
		CertPEM:           c.CertPEM,
		FingerprintSHA256: c.Fingerprint,
		NotAfter:          c.NotAfter,
		Enabled:           c.Enabled,
		NetworkName:       c.NetworkName,
		CreatedAt:         c.CreatedAt,
	}
	// Subject と NotBefore は保存していないので、証明書から読む。
	if cert, err := certs.ParsePEM([]byte(c.CertPEM)); err == nil {
		out.Subject = cert.Subject.String()
		out.NotBefore = cert.NotBefore.UTC()
	}
	return out
}

func notFoundClient() *problem {
	return newProblem(http.StatusNotFound, causeClientNotFound, "client not found")
}

// parseClientCert はクライアント証明書の PEM を解析し、有効期間内であることを確認する。
func parseClientCert(pem string) (*x509.Certificate, *problem) {
	cert, err := certs.ParsePEM([]byte(pem))
	if err == nil {
		err = certs.CheckValidity(cert)
	}
	if err != nil {
		return nil, badParams(causeInvalidCertificate, invalidParam{"certPem", err.Error()})
	}
	return cert, nil
}

// clientID はパスのクライアントID を読む。不正なら 404 を書き込んで false を返す。
func clientID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("clientId"), 10, 64)
	if err != nil || id < 1 {
		notFoundClient().write(w)
		return 0, false
	}
	return id, true
}

// loadClient はパスのクライアントID の AVクライアントを読む。見つからなければ 404 を書き込んで false を返す。
func (h *Handler) loadClient(w http.ResponseWriter, r *http.Request) (store.Client, bool) {
	id, ok := clientID(w, r)
	if !ok {
		return store.Client{}, false
	}
	c, err := h.Store.GetClient(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		notFoundClient().write(w)
		return store.Client{}, false
	}
	if err != nil {
		h.internalError(w, r, err)
		return store.Client{}, false
	}
	return c, true
}

func (h *Handler) listClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.Store.ListClients(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	out := clientListJSON{Items: make([]clientJSON, len(clients))}
	for i, c := range clients {
		out.Items[i] = toClientJSON(c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) createClient(w http.ResponseWriter, r *http.Request) {
	var body clientCreateJSON
	if p := decodeBody(w, r, &body); p != nil {
		p.write(w)
		return
	}

	var v validation
	nc := store.NewClient{Enabled: true}
	switch {
	case body.Name == nil:
		v.missing = append(v.missing, invalidParam{"name", "is required"})
	case *body.Name == "" || len(*body.Name) > maxClientNameLen:
		v.mandatory = append(v.mandatory, invalidParam{"name", "must be 1 to 64 bytes"})
	default:
		nc.Name = *body.Name
	}
	if body.CertPEM == nil {
		v.missing = append(v.missing, invalidParam{"certPem", "is required"})
	}
	if body.Enabled != nil {
		nc.Enabled = *body.Enabled
	}
	if body.NetworkName != nil {
		if len(*body.NetworkName) > maxNetworkNameLen {
			v.optional = append(v.optional, invalidParam{"networkName", "must be at most 255 bytes"})
		}
		nc.NetworkName = *body.NetworkName
	}
	if p := v.problem(); p != nil {
		p.write(w)
		return
	}
	var p *problem
	if nc.Cert, p = parseClientCert(*body.CertPEM); p != nil {
		p.write(w)
		return
	}

	c, err := h.Store.CreateClient(r.Context(), nc)
	if errors.Is(err, store.ErrCertRegistered) {
		newProblem(http.StatusConflict, causeCertRegistered, "certificate is already registered").write(w)
		return
	}
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	id := strconv.FormatInt(c.ID, 10)
	h.audit(r, "client.create", id, map[string]any{
		"name": c.Name, "fingerprintSha256": c.Fingerprint, "enabled": c.Enabled, "networkName": c.NetworkName,
	})
	w.Header().Set("Location", "/admin/v1/clients/"+id)
	writeJSON(w, http.StatusCreated, toClientJSON(c))
}

func (h *Handler) getClient(w http.ResponseWriter, r *http.Request) {
	if c, ok := h.loadClient(w, r); ok {
		writeJSON(w, http.StatusOK, toClientJSON(c))
	}
}

func (h *Handler) updateClient(w http.ResponseWriter, r *http.Request) {
	fields, p := decodePatch(w, r)
	if p != nil {
		p.write(w)
		return
	}
	var v validation
	patch := store.ClientPatch{
		Name:        patchField[string](fields, "name", &v),
		Enabled:     patchField[bool](fields, "enabled", &v),
		NetworkName: patchField[string](fields, "networkName", &v),
	}
	if patch.Name != nil && (*patch.Name == "" || len(*patch.Name) > maxClientNameLen) {
		v.optional = append(v.optional, invalidParam{"name", "must be 1 to 64 bytes"})
	}
	if patch.NetworkName != nil && len(*patch.NetworkName) > maxNetworkNameLen {
		v.optional = append(v.optional, invalidParam{"networkName", "must be at most 255 bytes"})
	}
	rejectUnknown(fields, &v)
	if p := v.problem(); p != nil {
		p.write(w)
		return
	}

	before, ok := h.loadClient(w, r)
	if !ok {
		return
	}
	err := h.Store.UpdateClient(r.Context(), before.ID, patch)
	if errors.Is(err, store.ErrNotFound) {
		notFoundClient().write(w)
		return
	}
	if err != nil {
		h.internalError(w, r, err)
		return
	}

	detail := map[string]any{}
	if patch.Name != nil {
		detail["name"] = change{before.Name, *patch.Name}
	}
	if patch.Enabled != nil {
		detail["enabled"] = change{before.Enabled, *patch.Enabled}
	}
	if patch.NetworkName != nil {
		detail["networkName"] = change{before.NetworkName, *patch.NetworkName}
	}
	h.audit(r, "client.update", strconv.FormatInt(before.ID, 10), detail)

	if after, ok := h.loadClient(w, r); ok {
		writeJSON(w, http.StatusOK, toClientJSON(after))
	}
}

func (h *Handler) replaceClientCertificate(w http.ResponseWriter, r *http.Request) {
	var body clientCertificateJSON
	if p := decodeBody(w, r, &body); p != nil {
		p.write(w)
		return
	}
	if body.CertPEM == nil {
		badParams(causeMandatoryIEMissing, invalidParam{"certPem", "is required"}).write(w)
		return
	}
	cert, p := parseClientCert(*body.CertPEM)
	if p != nil {
		p.write(w)
		return
	}

	before, ok := h.loadClient(w, r)
	if !ok {
		return
	}
	err := h.Store.ReplaceClientCertificate(r.Context(), before.ID, cert)
	switch {
	case errors.Is(err, store.ErrNotFound):
		notFoundClient().write(w)
		return
	case errors.Is(err, store.ErrCertRegistered):
		newProblem(http.StatusConflict, causeCertRegistered, "certificate is already registered to another client").write(w)
		return
	case err != nil:
		h.internalError(w, r, err)
		return
	}
	h.audit(r, "client.certificate.replace", strconv.FormatInt(before.ID, 10), map[string]any{
		"fingerprintSha256": change{before.Fingerprint, certs.Fingerprint(cert)},
	})

	if after, ok := h.loadClient(w, r); ok {
		writeJSON(w, http.StatusOK, toClientJSON(after))
	}
}

func (h *Handler) deleteClient(w http.ResponseWriter, r *http.Request) {
	c, ok := h.loadClient(w, r)
	if !ok {
		return
	}
	err := h.Store.DeleteClient(r.Context(), c.ID)
	if errors.Is(err, store.ErrNotFound) {
		notFoundClient().write(w)
		return
	}
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	h.audit(r, "client.delete", strconv.FormatInt(c.ID, 10), map[string]any{
		"name": c.Name, "fingerprintSha256": c.Fingerprint,
	})

	// 各加入者の許可クライアントからの除去は、応答を返した後に行う。
	// ID を再利用しないので、これが途中で止まっても別のクライアントが許可されることはない。
	trace := traceID(r)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), purgeTimeout)
		defer cancel()
		if err := h.Store.PurgeClientFromSubscribers(ctx, c.ID); err != nil {
			h.Log.Error("purge deleted client from subscribers", "trace_id", trace, "client_id", c.ID, "error", err)
		}
	}()
	w.WriteHeader(http.StatusNoContent)
}
