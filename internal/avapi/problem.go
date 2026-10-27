package avapi

import (
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
)

// ProblemDetails の cause の値（認証ベクターAPI の契約 §9.1）。
const (
	causeInvalidMsgFormat     = "INVALID_MSG_FORMAT"
	causeMandatoryIEMissing   = "MANDATORY_IE_MISSING"
	causeMandatoryIEIncorrect = "MANDATORY_IE_INCORRECT"
	causeOptionalIEIncorrect  = "OPTIONAL_IE_INCORRECT"
	causeAuthRejected         = "AUTHENTICATION_REJECTED"
	causeSystemFailure        = "SYSTEM_FAILURE"
	causeAuthTypeNotSupported = "AUTH_TYPE_NOT_SUPPORTED"
	causeNFCongestion         = "NF_CONGESTION"
)

// 一般的な拒否の理由（契約 §9.2）。応答には出さず、ログにだけ残す。
const (
	ReasonNotFound         = "not_found"
	ReasonClientNotAllowed = "client_not_allowed"
	ReasonInactive         = "inactive"
	ReasonTerminated       = "terminated"
	ReasonAUTSInvalid      = "auts_invalid"
	ReasonClientDisabled   = "client_disabled"
	ReasonClientUnknown    = "client_unknown"
)

// problemDetails は TS 29.571 の ProblemDetails のうち、このサーバーが返す項目。
type problemDetails struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Cause  string `json:"cause"`
}

// problem はハンドラー内でエラー応答を表す。
type problem struct {
	status int
	cause  string
	detail string
	// reason は一般的な拒否の理由。ログにだけ残し、応答には出さない。
	reason string
}

func (p *problem) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.status)
	json.MarshalWrite(w, problemDetails{
		Title:  http.StatusText(p.status),
		Status: p.status,
		Detail: p.detail,
		Cause:  p.cause,
	})
}

// rejected は一般的な拒否（契約 §9.2）を表す。どの理由でも同じステータス・同じ本文になる（detail は入れない）。
func rejected(reason string) *problem {
	return &problem{status: http.StatusForbidden, cause: causeAuthRejected, reason: reason}
}

// WriteRejected は一般的な拒否を書き込む。クライアントを識別できなかった場合に、ハンドラーの外側から使う。
// 理由は呼び出し側がログに残す。
func WriteRejected(w http.ResponseWriter) {
	rejected("").write(w)
}

// WriteInternalError は 500（SYSTEM_FAILURE）の ProblemDetails を書き込む。
func WriteInternalError(w http.ResponseWriter) {
	(&problem{status: http.StatusInternalServerError, cause: causeSystemFailure}).write(w)
}

func badRequest(cause, detail string) *problem {
	return &problem{status: http.StatusBadRequest, cause: cause, detail: detail}
}

// internalError は中の誤りを表す。保存先（Valkey）に届かないときは 503（NF_CONGESTION）、
// それ以外は 500（SYSTEM_FAILURE）にする（設計概要の決定事項 10）。detail はログにだけ残す。
func internalError(err error) *problem {
	if _, ok := errors.AsType[net.Error](err); ok {
		return &problem{status: http.StatusServiceUnavailable, cause: causeNFCongestion, detail: err.Error()}
	}
	return &problem{status: http.StatusInternalServerError, cause: causeSystemFailure, detail: err.Error()}
}
