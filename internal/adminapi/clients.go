package adminapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/certs"
	"github.com/oyaguma3/aka-vecgen/internal/store"
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

func (h *Handler) getClient(w http.ResponseWriter, r *http.Request) {
	if c, ok := h.loadClient(w, r); ok {
		writeJSON(w, http.StatusOK, toClientJSON(c))
	}
}
