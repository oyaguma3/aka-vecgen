// Package avapi は認証ベクターAPI（TS 29.503 GenerateAv ベース）を提供する。
// API 仕様は docs/openapi/av-api.yaml を参照。
package avapi

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/oyaguma3/aka-vecgen/internal/aka"
	"github.com/oyaguma3/aka-vecgen/internal/store"
	"github.com/oyaguma3/aka-vecgen/internal/traceid"
)

// DefaultNetworkName は、クライアントに Network Name が設定されていない場合に
// EAP-AKA' の鍵導出で使う値。
const DefaultNetworkName = "WLAN"

const (
	maxVectors   = 5
	maxBodyBytes = 64 << 10
)

// Allocator は許可判定と SQN の払い出しを行う。
type Allocator interface {
	Allocate(ctx context.Context, req store.AllocateRequest) (store.Allocation, error)
}

// Handler は認証ベクターAPI のハンドラー。
type Handler struct {
	Allocator Allocator
	Log       *slog.Logger
	// ClientID はリクエストからクライアントID を取り出す。平文HTTP リスナーでは 0 を返す。
	ClientID func(*http.Request) int64
}

// Routes は認証ベクターAPI のルーティングを返す。
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /nudm-ueau/v1/{supi}/hss-security-information/{hssAuthType}/generate-av", h.generateAV)
	return mux
}

// authType は対応する認証タイプ。
type authType struct {
	body  string // リクエストボディとレスポンスでの表記
	prime bool   // EAP-AKA' か
}

// パスの hssAuthType から認証タイプを引く。
var authTypes = map[string]authType{
	"eap-aka":       {body: "EAP_AKA"},
	"umts-aka":      {body: "UMTS_AKA"},
	"eap-aka-prime": {body: "EAP_AKA_PRIME", prime: true},
}

// TS 29.503 にはあるが、このサーバーが対応しない認証タイプ。
var unsupportedAuthTypes = []string{"eps-aka", "ims-aka", "gba-aka"}

var supiPattern = regexp.MustCompile(`^imsi-[0-9]{5,15}$`)

type resyncInfo struct {
	RAND string `json:"rand"`
	AUTS string `json:"auts"`
}

// generateAVRequest は HssAuthenticationInfoRequest のうち、このサーバーが使う項目。
// それ以外の項目は無視する。
type generateAVRequest struct {
	HSSAuthType           *string     `json:"hssAuthType"`
	NumOfRequestedVectors *int        `json:"numOfRequestedVectors"`
	ResynchronizationInfo *resyncInfo `json:"resynchronizationInfo"`
	AnID                  *string     `json:"anId"`
}

// authVector は AvImsGbaEapAka と AvEapAkaPrime を兼ねる。
type authVector struct {
	AVType  string `json:"avType"`
	RAND    string `json:"rand"`
	XRES    string `json:"xres"`
	AUTN    string `json:"autn"`
	CK      string `json:"ck,omitempty"`
	IK      string `json:"ik,omitempty"`
	CKPrime string `json:"ckPrime,omitempty"`
	IKPrime string `json:"ikPrime,omitempty"`
}

type generateAVResponse struct {
	HSSAuthenticationVectors []authVector `json:"hssAuthenticationVectors"`
}

// parsedRequest は検証済みのリクエスト。
type parsedRequest struct {
	imsi     string
	authType authType
	n        int
	resync   bool
	rand     []byte // resync が true のとき有効
	auts     []byte // resync が true のとき有効
	anID     string // EAP-AKA' で指定された場合のみ
}

func (h *Handler) generateAV(w http.ResponseWriter, r *http.Request) {
	// 呼び出し元（本PoC の vector-gateway）が X-Trace-ID を送っていればログに残し、1 回の認証を
	// 呼び出し元のログとつなげられるようにする。なければ採番する。どちらも応答のヘッダーで返す。
	traceID := traceid.Resolve(r.Header.Get(traceid.Header))
	w.Header().Set(traceid.Header, traceID)
	clientID := h.ClientID(r)
	log := h.Log.With("trace_id", traceID, "client_id", clientID, "remote", r.RemoteAddr)

	req, p := parseRequest(w, r)
	if p != nil {
		log.Warn("av request rejected", "cause", p.cause, "detail", p.detail)
		p.write(w)
		return
	}
	log = log.With("imsi", req.imsi, "auth_type", req.authType.body, "n", req.n, "resync", req.resync)

	vectors, p := h.generate(r.Context(), clientID, req)
	if p != nil {
		if p.status >= http.StatusInternalServerError {
			log.Error("av request failed", "cause", p.cause, "detail", p.detail)
			// 内部エラーの詳細はクライアントに返さない。
			p.detail = ""
		} else {
			log.Warn("av request rejected", "cause", p.cause, "detail", p.detail)
		}
		p.write(w)
		return
	}

	log.Info("av generated")
	w.Header().Set("Content-Type", "application/json")
	json.MarshalWrite(w, generateAVResponse{HSSAuthenticationVectors: vectors})
}

func parseRequest(w http.ResponseWriter, r *http.Request) (parsedRequest, *problem) {
	var req parsedRequest

	pathType := r.PathValue("hssAuthType")
	at, ok := authTypes[pathType]
	if !ok {
		if slices.Contains(unsupportedAuthTypes, pathType) {
			return req, &problem{status: http.StatusNotImplemented, cause: causeAuthTypeNotSupported,
				detail: "auth type " + pathType + " is not supported"}
		}
		return req, badRequest(causeMandatoryIEIncorrect, "unknown hssAuthType in path")
	}
	req.authType = at

	supi := r.PathValue("supi")
	if !supiPattern.MatchString(supi) {
		return req, badRequest(causeMandatoryIEIncorrect, "supi must be imsi-<5 to 15 digits>")
	}
	req.imsi = strings.TrimPrefix(supi, "imsi-")

	var body generateAVRequest
	if err := json.UnmarshalRead(http.MaxBytesReader(w, r.Body, maxBodyBytes), &body); err != nil {
		return req, badRequest(causeInvalidMsgFormat, "request body is not valid JSON for this operation")
	}
	if body.HSSAuthType == nil {
		return req, badRequest(causeMandatoryIEMissing, "hssAuthType is required")
	}
	if body.NumOfRequestedVectors == nil {
		return req, badRequest(causeMandatoryIEMissing, "numOfRequestedVectors is required")
	}
	if *body.HSSAuthType != at.body {
		return req, badRequest(causeMandatoryIEIncorrect, "hssAuthType does not match the path")
	}
	req.n = *body.NumOfRequestedVectors
	if req.n < 1 || req.n > maxVectors {
		return req, badRequest(causeMandatoryIEIncorrect, "numOfRequestedVectors must be between 1 and 5")
	}

	if ri := body.ResynchronizationInfo; ri != nil {
		var err error
		if req.rand, err = hex.DecodeString(ri.RAND); err != nil || len(req.rand) != 16 {
			return req, badRequest(causeOptionalIEIncorrect, "resynchronizationInfo.rand must be 32 hex digits")
		}
		if req.auts, err = hex.DecodeString(ri.AUTS); err != nil || len(req.auts) != 14 {
			return req, badRequest(causeOptionalIEIncorrect, "resynchronizationInfo.auts must be 28 hex digits")
		}
		req.resync = true
	}

	// anId は EAP-AKA' 以外では無視する。
	if at.prime && body.AnID != nil {
		if *body.AnID == "" {
			return req, badRequest(causeOptionalIEIncorrect, "anId must not be empty")
		}
		req.anID = *body.AnID
	}
	return req, nil
}

func (h *Handler) generate(ctx context.Context, clientID int64, req parsedRequest) ([]authVector, *problem) {
	alloc := store.AllocateRequest{
		IMSI:               req.imsi,
		ClientID:           clientID,
		N:                  req.n,
		NetworkName:        req.anID,
		DefaultNetworkName: DefaultNetworkName,
	}

	if req.resync {
		// AUTS の検証には Ki と OPc が必要なので、まず SQN を進めずに読み出す。
		probe := alloc
		probe.N = 0
		cur, err := h.Allocator.Allocate(ctx, probe)
		if err != nil {
			return nil, allocateProblem(err)
		}
		sqnMS, err := aka.VerifyAUTS(cur.Credentials, req.rand, req.auts)
		if errors.Is(err, aka.ErrAUTSInvalid) {
			return nil, &problem{status: http.StatusForbidden, cause: causeAuthRejected, detail: "AUTS verification failed"}
		}
		if err != nil {
			return nil, internalError(err)
		}
		alloc.ResyncSQN = &sqnMS
	}

	a, err := h.Allocator.Allocate(ctx, alloc)
	if err != nil {
		return nil, allocateProblem(err)
	}
	sqns, err := a.SQNType.Sequence(a.Base, req.n)
	if err != nil {
		return nil, internalError(err)
	}

	vectors := make([]authVector, len(sqns))
	for i, sqn := range sqns {
		v, err := aka.Generate(a.Credentials, aka.NewRAND(), sqn)
		if err != nil {
			return nil, internalError(err)
		}
		av := authVector{
			AVType: req.authType.body,
			RAND:   hex.EncodeToString(v.RAND),
			XRES:   hex.EncodeToString(v.XRES),
			AUTN:   hex.EncodeToString(v.AUTN),
		}
		if req.authType.prime {
			ckPrime, ikPrime := aka.DerivePrime(v, a.NetworkName)
			av.CKPrime, av.IKPrime = hex.EncodeToString(ckPrime), hex.EncodeToString(ikPrime)
		} else {
			av.CK, av.IK = hex.EncodeToString(v.CK), hex.EncodeToString(v.IK)
		}
		vectors[i] = av
	}
	return vectors, nil
}

func allocateProblem(err error) *problem {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return &problem{status: http.StatusNotFound, cause: causeUserNotFound, detail: "subscriber not found"}
	case errors.Is(err, store.ErrForbidden):
		return &problem{status: http.StatusForbidden, cause: causeAuthRejected, detail: "client is not allowed for this subscriber"}
	case errors.Is(err, store.ErrNetworkNameMismatch):
		return badRequest(causeOptionalIEIncorrect, "anId does not match the configured network name")
	}
	return internalError(err)
}

func internalError(err error) *problem {
	return &problem{status: http.StatusInternalServerError, cause: causeSystemFailure, detail: err.Error()}
}
