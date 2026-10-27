package adminapi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oyaguma3/aka-vecgen/internal/aka"
	"github.com/oyaguma3/aka-vecgen/internal/store"
)

var (
	imsiPattern       = regexp.MustCompile(`^[0-9]{5,15}$`)
	imsiPrefixPattern = regexp.MustCompile(`^[0-9]{1,15}$`)
)

type subscriberJSON struct {
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

type subscriberCreateJSON struct {
	IMSI             *string  `json:"imsi"`
	Ki               *string  `json:"ki"`
	OPc              *string  `json:"opc"`
	State            *string  `json:"state"`
	SQN              *string  `json:"sqn"`
	AMF              *string  `json:"amf"`
	SQNType          *string  `json:"sqnType"`
	AllowedClientIDs *[]int64 `json:"allowedClientIds"`
}

type stateChangeJSON struct {
	State  *string `json:"state"`
	Reason *string `json:"reason"`
}

type reinstateJSON struct {
	Reason *string `json:"reason"`
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
		State:            string(sub.State),
		StateChangedAt:   sub.StateChangedAt,
		SQN:              formatSQN(sub.SQN),
		AMF:              formatAMF(sub.AMF),
		SQNType:          string(sub.SQNType),
		AllowedClientIDs: allowed,
		CreatedAt:        sub.CreatedAt,
		UpdatedAt:        sub.UpdatedAt,
	}
}

// subscriberState は監査ログに残す加入者の状態。Ki と OPc は含めない。
type subscriberState struct {
	State            string  `json:"state"`
	SQN              string  `json:"sqn"`
	AMF              string  `json:"amf"`
	SQNType          string  `json:"sqnType"`
	AllowedClientIDs []int64 `json:"allowedClientIds"`
}

func stateOf(sub store.Subscriber) subscriberState {
	return subscriberState{
		State:            string(sub.State),
		SQN:              formatSQN(sub.SQN),
		AMF:              formatAMF(sub.AMF),
		SQNType:          string(sub.SQNType),
		AllowedClientIDs: sub.AllowedClientIDs,
	}
}

// maxReasonLen は状態の変更の理由の文字数の上限。
const maxReasonLen = 500

// parseReason は理由を読む。required なら空を断る。
func parseReason(s *string, required bool, v *validation) string {
	if s == nil || strings.TrimSpace(*s) == "" {
		if required {
			v.missing = append(v.missing, invalidParam{"reason", "is required"})
		}
		return ""
	}
	if utf8.RuneCountInString(*s) > maxReasonLen {
		v.optional = append(v.optional, invalidParam{"reason", "must be at most 500 characters"})
		return ""
	}
	return *s
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
	// 登録のときの状態は active か inactive（設計概要 §7.1）。
	switch {
	case body.State == nil:
		v.missing = append(v.missing, invalidParam{"state", "is required"})
	case *body.State != string(store.StateActive) && *body.State != string(store.StateInactive):
		v.mandatory = append(v.mandatory, invalidParam{"state", "must be active or inactive"})
	default:
		sub.State = store.State(*body.State)
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
	w.Header().Set("Location", "/admin/v2/subscribers/"+sub.IMSI)
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
	// 鍵は登録の後に変えない（設計概要の決定事項 4）。状態は専用の口で変える。
	for _, name := range []string{"ki", "opc"} {
		if _, ok := fields[name]; ok {
			delete(fields, name)
			v.optional = append(v.optional, invalidParam{name, "cannot be changed after registration; set the subscriber inactive, delete it and register it again"})
		}
	}
	if _, ok := fields["state"]; ok {
		delete(fields, "state")
		v.optional = append(v.optional, invalidParam{"state", "use PUT /subscribers/{imsi}/state or POST /subscribers/{imsi}/reinstate"})
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
	case errors.Is(err, store.ErrTerminated):
		newProblem(http.StatusConflict, causeSubscriberTerminated, "a terminated subscriber cannot be changed").write(w)
		return
	case errors.Is(err, store.ErrUnknownClient):
		badParams(causeClientNotFound, invalidParam{"allowedClientIds", err.Error()}).write(w)
		return
	case err != nil:
		h.internalError(w, r, err)
		return
	}

	// 監査ログには、指定された項目の前後の値を残す。
	detail := map[string]any{}
	if patch.SQN != nil {
		detail["sqn"] = change{formatSQN(before.SQN), formatSQN(*patch.SQN)}
	}
	if patch.AMF != nil {
		detail["amf"] = change{formatAMF(before.AMF), formatAMF(*patch.AMF)}
	}
	if patch.SQNType != nil {
		detail["sqnType"] = change{before.SQNType, *patch.SQNType}
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
	switch {
	case errors.Is(err, store.ErrNotFound):
		notFoundSubscriber().write(w)
		return
	case errors.Is(err, store.ErrActive):
		newProblem(http.StatusConflict, causeSubscriberActive, "an active subscriber cannot be deleted; set it inactive or terminated first").write(w)
		return
	case err != nil:
		h.internalError(w, r, err)
		return
	}
	// 削除して再登録することで SQN / AMF を実質的に変更した操作を追跡できるよう、削除時点の値を残す。
	h.audit(r, "subscriber.delete", sub.IMSI, stateOf(sub))
	w.WriteHeader(http.StatusNoContent)
}

// setSubscriberState は状態を変える（active ⇔ inactive、terminated へ）。terminated からは reinstate だけで戻す。
// 同じ状態への変更は何もせず 200 を返し、監査ログには残す（設計概要 §7.1）。
func (h *Handler) setSubscriberState(w http.ResponseWriter, r *http.Request) {
	var body stateChangeJSON
	if p := decodeBody(w, r, &body); p != nil {
		p.write(w)
		return
	}
	var v validation
	var to store.State
	switch {
	case body.State == nil:
		v.missing = append(v.missing, invalidParam{"state", "is required"})
	case !store.State(*body.State).Valid():
		v.mandatory = append(v.mandatory, invalidParam{"state", "must be active, inactive or terminated"})
	default:
		to = store.State(*body.State)
	}
	reason := parseReason(body.Reason, false, &v)
	if p := v.problem(); p != nil {
		p.write(w)
		return
	}
	imsi := r.PathValue("imsi")
	if !imsiPattern.MatchString(imsi) {
		notFoundSubscriber().write(w)
		return
	}
	from, unchanged, err := h.Store.SetState(r.Context(), imsi, to)
	switch {
	case errors.Is(err, store.ErrNotFound):
		notFoundSubscriber().write(w)
		return
	case errors.Is(err, store.ErrTransitionNotAllowed):
		newProblem(http.StatusConflict, causeTransitionNotAllowed,
			"a terminated subscriber can only be returned to inactive with POST /subscribers/{imsi}/reinstate").write(w)
		return
	case err != nil:
		h.internalError(w, r, err)
		return
	}
	detail := map[string]any{"state": change{from, to}}
	if unchanged {
		detail["unchanged"] = true
	}
	if reason != "" {
		detail["reason"] = reason
	}
	h.audit(r, "subscriber.state", imsi, detail)
	if after, ok := h.loadSubscriber(w, r); ok {
		h.writeSubscriber(w, r, after)
	}
}

// reinstateSubscriber は terminated の加入者を inactive に戻す。理由は必須（設計概要 §7.2）。
// システム管理者だけに許すことは aka-ossbss が守る。
func (h *Handler) reinstateSubscriber(w http.ResponseWriter, r *http.Request) {
	var body reinstateJSON
	if p := decodeBody(w, r, &body); p != nil {
		p.write(w)
		return
	}
	var v validation
	reason := parseReason(body.Reason, true, &v)
	if p := v.problem(); p != nil {
		p.write(w)
		return
	}
	imsi := r.PathValue("imsi")
	if !imsiPattern.MatchString(imsi) {
		notFoundSubscriber().write(w)
		return
	}
	from, err := h.Store.Reinstate(r.Context(), imsi)
	switch {
	case errors.Is(err, store.ErrNotFound):
		notFoundSubscriber().write(w)
		return
	case errors.Is(err, store.ErrTransitionNotAllowed):
		newProblem(http.StatusConflict, causeTransitionNotAllowed, "only a terminated subscriber can be reinstated").write(w)
		return
	case err != nil:
		h.internalError(w, r, err)
		return
	}
	h.audit(r, "subscriber.reinstate", imsi, map[string]any{"state": change{from, store.StateInactive}, "reason": reason})
	if after, ok := h.loadSubscriber(w, r); ok {
		h.writeSubscriber(w, r, after)
	}
}

func (h *Handler) getSubscriberKeys(w http.ResponseWriter, r *http.Request) {
	// 鍵の読み出しは既定で無効（VECGEN_KEY_EXPORT=true のときだけ。設計概要 §8.4）
	if !h.KeyExport {
		newProblem(http.StatusNotFound, causeKeyExportDisabled, "key export is disabled (VECGEN_KEY_EXPORT)").write(w)
		return
	}
	sub, ok := h.loadSubscriber(w, r)
	if !ok {
		return
	}
	ki, opc, err := h.Store.SubscriberKeys(r.Context(), sub.IMSI)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	h.audit(r, "subscriber.keys.read", sub.IMSI, nil)
	writeJSON(w, http.StatusOK, subscriberKeysJSON{Ki: hex.EncodeToString(ki), OPc: hex.EncodeToString(opc)})
	clear(ki)
	clear(opc)
}

// maxBatchGet は一括取得で受け付ける IMSI の数の上限（設計概要 §6.2）。
const maxBatchGet = 500

type batchGetJSON struct {
	IMSIs *[]string `json:"imsis"`
}

type batchGetResultJSON struct {
	Items    []subscriberJSON `json:"items"`
	NotFound []string         `json:"notFound"`
}

// batchGetSubscribers は IMSI を 500 件まで受け取り、ある加入者（鍵を除く）と、ない IMSI を返す（設計概要 §6.2）。
// 台帳との突き合わせと一括投入の前の確認に使う。重なった IMSI は 1 つにまとめ、応答は要求の順にする。
func (h *Handler) batchGetSubscribers(w http.ResponseWriter, r *http.Request) {
	var body batchGetJSON
	if p := decodeBody(w, r, &body); p != nil {
		p.write(w)
		return
	}
	switch {
	case body.IMSIs == nil:
		badParams(causeMandatoryIEMissing, invalidParam{"imsis", "is required"}).write(w)
		return
	case len(*body.IMSIs) == 0 || len(*body.IMSIs) > maxBatchGet:
		badParams(causeMandatoryIEIncorrect, invalidParam{"imsis", fmt.Sprintf("must have 1 to %d items", maxBatchGet)}).write(w)
		return
	}
	var imsis []string
	seen := map[string]bool{}
	for i, imsi := range *body.IMSIs {
		if !imsiPattern.MatchString(imsi) {
			badParams(causeMandatoryIEIncorrect, invalidParam{fmt.Sprintf("imsis[%d]", i), "must be 5 to 15 digits"}).write(w)
			return
		}
		if !seen[imsi] {
			seen[imsi] = true
			imsis = append(imsis, imsi)
		}
	}
	subs, err := h.Store.GetSubscribers(r.Context(), imsis)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	clientIDs, err := h.Store.ClientIDs(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	found := map[string]store.Subscriber{}
	for _, sub := range subs {
		found[sub.IMSI] = sub
	}
	out := batchGetResultJSON{Items: []subscriberJSON{}, NotFound: []string{}}
	for _, imsi := range imsis {
		if sub, ok := found[imsi]; ok {
			out.Items = append(out.Items, toSubscriberJSON(sub, clientIDs))
		} else {
			out.NotFound = append(out.NotFound, imsi)
		}
	}
	writeJSON(w, http.StatusOK, out)
}
