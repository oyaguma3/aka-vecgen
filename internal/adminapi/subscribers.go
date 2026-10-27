package adminapi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/oyaguma3/aka-vecgen/internal/aka"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

var (
	imsiPattern       = regexp.MustCompile(`^[0-9]{5,15}$`)
	imsiPrefixPattern = regexp.MustCompile(`^[0-9]{1,15}$`)
)

type subscriberJSON struct {
	IMSI             string    `json:"imsi"`
	SQN              string    `json:"sqn"`
	AMF              string    `json:"amf"`
	SQNType          string    `json:"sqnType"`
	AllowPlain       bool      `json:"allowPlain"`
	AllowedClientIDs []int64   `json:"allowedClientIds"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type subscriberCreateJSON struct {
	IMSI             *string  `json:"imsi"`
	Ki               *string  `json:"ki"`
	OPc              *string  `json:"opc"`
	SQN              *string  `json:"sqn"`
	AMF              *string  `json:"amf"`
	SQNType          *string  `json:"sqnType"`
	AllowPlain       *bool    `json:"allowPlain"`
	AllowedClientIDs *[]int64 `json:"allowedClientIds"`
}

type subscriberListJSON struct {
	Items      []subscriberJSON `json:"items"`
	Total      int64            `json:"total"`
	NextCursor string           `json:"nextCursor,omitempty"`
}

type subscriberKeysJSON struct {
	Ki  string `json:"ki"`
	OPc string `json:"opc"`
}

func formatSQN(sqn uint64) string { return fmt.Sprintf("%012x", sqn) }
func formatAMF(amf uint16) string { return fmt.Sprintf("%04x", amf) }

// toSubscriberJSON は応答用の表現を作る。削除済みクライアントの ID は含めない。
func toSubscriberJSON(sub store.Subscriber, clientIDs []int64) subscriberJSON {
	allowed := make([]int64, 0, len(sub.AllowedClientIDs))
	for _, id := range sub.AllowedClientIDs {
		if slices.Contains(clientIDs, id) {
			allowed = append(allowed, id)
		}
	}
	return subscriberJSON{
		IMSI:             sub.IMSI,
		SQN:              formatSQN(sub.SQN),
		AMF:              formatAMF(sub.AMF),
		SQNType:          string(sub.SQNType),
		AllowPlain:       sub.AllowPlain,
		AllowedClientIDs: allowed,
		CreatedAt:        sub.CreatedAt,
		UpdatedAt:        sub.UpdatedAt,
	}
}

// subscriberState は監査ログに残す加入者の状態。Ki と OPc は含めない。
type subscriberState struct {
	SQN              string  `json:"sqn"`
	AMF              string  `json:"amf"`
	SQNType          string  `json:"sqnType"`
	AllowPlain       bool    `json:"allowPlain"`
	AllowedClientIDs []int64 `json:"allowedClientIds"`
}

func stateOf(sub store.Subscriber) subscriberState {
	return subscriberState{
		SQN:              formatSQN(sub.SQN),
		AMF:              formatAMF(sub.AMF),
		SQNType:          string(sub.SQNType),
		AllowPlain:       sub.AllowPlain,
		AllowedClientIDs: sub.AllowedClientIDs,
	}
}

func parseHex(s string, size int) ([]byte, bool) {
	b, err := hex.DecodeString(s)
	return b, err == nil && len(b) == size
}

func parseSQN(s string) (uint64, bool) {
	if len(s) != 12 {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 64)
	return v, err == nil
}

func parseAMF(s string) (uint16, bool) {
	if len(s) != 4 {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 16)
	return uint16(v), err == nil
}

// normalizeClientIDs は重複を除いて昇順にそろえる。1 未満の ID があれば false を返す。
func normalizeClientIDs(ids []int64) ([]int64, bool) {
	out := slices.Clone(ids)
	slices.Sort(out)
	out = slices.Compact(out)
	return out, len(out) == 0 || out[0] >= 1
}

func notFoundSubscriber() *problem {
	return newProblem(http.StatusNotFound, causeUserNotFound, "subscriber not found")
}

func (h *Handler) listSubscribers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	prefix, cursor := q.Get("prefix"), q.Get("cursor")
	if prefix != "" && !imsiPrefixPattern.MatchString(prefix) {
		badParams(causeInvalidQueryParam, invalidParam{"prefix", "must be 1 to 15 digits"}).write(w)
		return
	}
	if cursor != "" && !imsiPattern.MatchString(cursor) {
		badParams(causeInvalidQueryParam, invalidParam{"cursor", "must be a nextCursor value from a previous response"}).write(w)
		return
	}
	limit, p := queryInt(r, "limit", 50, 1, 500)
	if p != nil {
		p.write(w)
		return
	}

	page, err := h.Store.ListSubscribers(r.Context(), prefix, cursor, int(limit))
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	clientIDs, err := h.Store.ClientIDs(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	out := subscriberListJSON{Items: make([]subscriberJSON, len(page.Items)), Total: page.Total, NextCursor: page.NextCursor}
	for i, sub := range page.Items {
		out.Items[i] = toSubscriberJSON(sub, clientIDs)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) createSubscriber(w http.ResponseWriter, r *http.Request) {
	var body subscriberCreateJSON
	if p := decodeBody(w, r, &body); p != nil {
		p.write(w)
		return
	}

	var v validation
	sub := store.Subscriber{AMF: 0x8000, SQNType: aka.SQNInc32}
	var ok bool

	switch {
	case body.IMSI == nil:
		v.missing = append(v.missing, invalidParam{"imsi", "is required"})
	case !imsiPattern.MatchString(*body.IMSI):
		v.mandatory = append(v.mandatory, invalidParam{"imsi", "must be 5 to 15 digits"})
	default:
		sub.IMSI = *body.IMSI
	}
	if body.Ki == nil {
		v.missing = append(v.missing, invalidParam{"ki", "is required"})
	} else if sub.Ki, ok = parseHex(*body.Ki, 16); !ok {
		v.mandatory = append(v.mandatory, invalidParam{"ki", "must be 32 hex digits"})
	}
	if body.OPc == nil {
		v.missing = append(v.missing, invalidParam{"opc", "is required"})
	} else if sub.OPc, ok = parseHex(*body.OPc, 16); !ok {
		v.mandatory = append(v.mandatory, invalidParam{"opc", "must be 32 hex digits"})
	}
	if body.SQN != nil {
		if sub.SQN, ok = parseSQN(*body.SQN); !ok {
			v.optional = append(v.optional, invalidParam{"sqn", "must be 12 hex digits"})
		}
	}
	if body.AMF != nil {
		if sub.AMF, ok = parseAMF(*body.AMF); !ok {
			v.optional = append(v.optional, invalidParam{"amf", "must be 4 hex digits"})
		}
	}
	if body.SQNType != nil {
		if sub.SQNType = aka.SQNType(*body.SQNType); !sub.SQNType.Valid() {
			v.optional = append(v.optional, invalidParam{"sqnType", "must be inc1, inc32 or inc33"})
		}
	}
	if body.AllowPlain != nil {
		sub.AllowPlain = *body.AllowPlain
	}
	if body.AllowedClientIDs != nil {
		if sub.AllowedClientIDs, ok = normalizeClientIDs(*body.AllowedClientIDs); !ok {
			v.optional = append(v.optional, invalidParam{"allowedClientIds", "client ids must be 1 or greater"})
		}
	}
	if p := v.problem(); p != nil {
		p.write(w)
		return
	}

	err := h.Store.CreateSubscriber(r.Context(), sub)
	switch {
	case errors.Is(err, store.ErrExists):
		newProblem(http.StatusConflict, causeSubscriberExists, "subscriber already exists").write(w)
		return
	case errors.Is(err, store.ErrUnknownClient):
		badParams(causeClientNotFound, invalidParam{"allowedClientIds", err.Error()}).write(w)
		return
	case err != nil:
		h.internalError(w, r, err)
		return
	}
	h.audit(r, "subscriber.create", sub.IMSI, stateOf(sub))

	created, err := h.Store.GetSubscriber(r.Context(), sub.IMSI)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	w.Header().Set("Location", "/admin/v1/subscribers/"+sub.IMSI)
	// 登録時に存在を確認済みなので、指定された ID をそのまま返す。
	writeJSON(w, http.StatusCreated, toSubscriberJSON(created, created.AllowedClientIDs))
}

// loadSubscriber はパスの IMSI の加入者を読む。見つからなければ 404 を書き込んで false を返す。
func (h *Handler) loadSubscriber(w http.ResponseWriter, r *http.Request) (store.Subscriber, bool) {
	imsi := r.PathValue("imsi")
	if !imsiPattern.MatchString(imsi) {
		notFoundSubscriber().write(w)
		return store.Subscriber{}, false
	}
	sub, err := h.Store.GetSubscriber(r.Context(), imsi)
	if errors.Is(err, store.ErrNotFound) {
		notFoundSubscriber().write(w)
		return store.Subscriber{}, false
	}
	if err != nil {
		h.internalError(w, r, err)
		return store.Subscriber{}, false
	}
	return sub, true
}

// writeSubscriber は加入者を応答として書き込む。
func (h *Handler) writeSubscriber(w http.ResponseWriter, r *http.Request, sub store.Subscriber) {
	clientIDs, err := h.Store.ClientIDs(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toSubscriberJSON(sub, clientIDs))
}

func (h *Handler) getSubscriber(w http.ResponseWriter, r *http.Request) {
	if sub, ok := h.loadSubscriber(w, r); ok {
		h.writeSubscriber(w, r, sub)
	}
}

// change は監査ログに残す変更前後の値。
type change struct {
	From any `json:"from"`
	To   any `json:"to"`
}

func (h *Handler) updateSubscriber(w http.ResponseWriter, r *http.Request) {
	fields, p := decodePatch(w, r)
	if p != nil {
		p.write(w)
		return
	}

	var v validation
	var patch store.SubscriberPatch
	var ok bool
	if s := patchField[string](fields, "ki", &v); s != nil {
		if patch.Ki, ok = parseHex(*s, 16); !ok {
			v.optional = append(v.optional, invalidParam{"ki", "must be 32 hex digits"})
		}
	}
	if s := patchField[string](fields, "opc", &v); s != nil {
		if patch.OPc, ok = parseHex(*s, 16); !ok {
			v.optional = append(v.optional, invalidParam{"opc", "must be 32 hex digits"})
		}
	}
	if s := patchField[string](fields, "sqn", &v); s != nil {
		if sqn, ok := parseSQN(*s); ok {
			patch.SQN = &sqn
		} else {
			v.optional = append(v.optional, invalidParam{"sqn", "must be 12 hex digits"})
		}
	}
	if s := patchField[string](fields, "amf", &v); s != nil {
		if amf, ok := parseAMF(*s); ok {
			patch.AMF = &amf
		} else {
			v.optional = append(v.optional, invalidParam{"amf", "must be 4 hex digits"})
		}
	}
	if s := patchField[string](fields, "sqnType", &v); s != nil {
		if t := aka.SQNType(*s); t.Valid() {
			patch.SQNType = &t
		} else {
			v.optional = append(v.optional, invalidParam{"sqnType", "must be inc1, inc32 or inc33"})
		}
	}
	patch.AllowPlain = patchField[bool](fields, "allowPlain", &v)
	if ids := patchField[[]int64](fields, "allowedClientIds", &v); ids != nil {
		if norm, ok := normalizeClientIDs(*ids); ok {
			patch.AllowedClientIDs = &norm
		} else {
			v.optional = append(v.optional, invalidParam{"allowedClientIds", "client ids must be 1 or greater"})
		}
	}
	rejectUnknown(fields, &v)
	if p := v.problem(); p != nil {
		p.write(w)
		return
	}

	before, found := h.loadSubscriber(w, r)
	if !found {
		return
	}
	err := h.Store.UpdateSubscriber(r.Context(), before.IMSI, patch)
	switch {
	case errors.Is(err, store.ErrNotFound):
		notFoundSubscriber().write(w)
		return
	case errors.Is(err, store.ErrUnknownClient):
		badParams(causeClientNotFound, invalidParam{"allowedClientIds", err.Error()}).write(w)
		return
	case err != nil:
		h.internalError(w, r, err)
		return
	}

	// 監査ログには、指定された項目の前後の値を残す。Ki と OPc は変更の有無だけを残す。
	detail := map[string]any{}
	if patch.Ki != nil {
		detail["kiChanged"] = true
	}
	if patch.OPc != nil {
		detail["opcChanged"] = true
	}
	if patch.SQN != nil {
		detail["sqn"] = change{formatSQN(before.SQN), formatSQN(*patch.SQN)}
	}
	if patch.AMF != nil {
		detail["amf"] = change{formatAMF(before.AMF), formatAMF(*patch.AMF)}
	}
	if patch.SQNType != nil {
		detail["sqnType"] = change{before.SQNType, *patch.SQNType}
	}
	if patch.AllowPlain != nil {
		detail["allowPlain"] = change{before.AllowPlain, *patch.AllowPlain}
	}
	if patch.AllowedClientIDs != nil {
		detail["allowedClientIds"] = change{before.AllowedClientIDs, *patch.AllowedClientIDs}
	}
	h.audit(r, "subscriber.update", before.IMSI, detail)

	if after, ok := h.loadSubscriber(w, r); ok {
		h.writeSubscriber(w, r, after)
	}
}

func (h *Handler) deleteSubscriber(w http.ResponseWriter, r *http.Request) {
	sub, ok := h.loadSubscriber(w, r)
	if !ok {
		return
	}
	err := h.Store.DeleteSubscriber(r.Context(), sub.IMSI)
	if errors.Is(err, store.ErrNotFound) {
		notFoundSubscriber().write(w)
		return
	}
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	// 削除して再登録することで SQN / AMF を実質的に変更した操作を追跡できるよう、削除時点の値を残す。
	h.audit(r, "subscriber.delete", sub.IMSI, stateOf(sub))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getSubscriberKeys(w http.ResponseWriter, r *http.Request) {
	sub, ok := h.loadSubscriber(w, r)
	if !ok {
		return
	}
	h.audit(r, "subscriber.keys.read", sub.IMSI, nil)
	writeJSON(w, http.StatusOK, subscriberKeysJSON{Ki: hex.EncodeToString(sub.Ki), OPc: hex.EncodeToString(sub.OPc)})
}
