package codearts

// 本文件实现华为云 CodeArts 的上游错误分类。
//
// 上游的错误有两个落点，两边都要认：
//   - HTTP 4xx/5xx 的响应体；
//   - HTTP 200 响应体 / SSE `data:` 帧里的业务错误信封（error_code + error_msg）。
//     后一种不识别就会被当成「流里没有 finish_reason」，被插件的通用错误覆盖，
//     用户看不到 benefit not found 这类可操作原因（issue #58）。

import (
	"encoding/json"
	"net/http"
	"strings"

	"freetier2api-plugin/internal/core"
)

const (
	// benefitCodeMarker 是「账号对该模型没有免费福利配额」的 InferHub 错误码前缀。
	benefitCodeMarker = "InferHub.4004.200"
	benefitMsgMarker  = "benefit not found"
	// benefitHint 是给用户的可操作提示，附在上游原文之后而不是替换它。
	benefitHint = "免费福利通道缺少有效权益；上游开放时可通过「一键签到」领取，签到无法恢复已关闭的通道。使用积分推理需明确开启 codearts_credit_enabled（会消耗账号积分）"
	// refreshTokenInvalidHint 是 refresh_token 失效时的处置指引。
	//
	// 华为云 STS 的 refresh_token 是「单次使用 + 轮转」的：用一次就作废，
	// 上游同时下发新的。这类失效（STS5.1804 / STS5.1806 / invalid_grant）
	// 没有任何自动恢复手段，只能重新登录。
	refreshTokenInvalidHint = "refresh_token 已失效（单次有效、用过即作废），请重新登录 CodeArts"
)

// errorEnvelope 是 CodeArts / InferHub 的业务错误信封。
//
// 与 OpenAI 的 {"error":{...}} 不是一回事：后者是已经翻译好的错误帧，
// 只有前者带 error_code / error_msg。
type errorEnvelope struct {
	ErrorCode    string          `json:"error_code"`
	ErrorMsg     string          `json:"error_msg"`
	ErrorMessage string          `json:"error_message"`
	Message      string          `json:"message"`
	Error        json.RawMessage `json:"error"`
	Details      []errorDetail   `json:"details"`
}

// errorDetail 是 details[] 的一条：上游把 requestId / traceId 塞在这里。
type errorDetail struct {
	ErrorCode string `json:"error_code"`
	ErrorMsg  string `json:"error_msg"`
}

// carriesError 报告信封里是否真的带业务错误。
func (e errorEnvelope) carriesError() bool {
	return strings.TrimSpace(e.ErrorCode) != "" || strings.TrimSpace(e.ErrorMsg) != ""
}

// errorField 返回 error 字段的字符串形态（有的接口把错误文案放在这里）。
func (e errorEnvelope) errorField() string {
	var text string
	if len(e.Error) > 0 && json.Unmarshal(e.Error, &text) == nil {
		return strings.TrimSpace(text)
	}
	return ""
}

// message 拼出给用户看的正文：上游原文 + requestId / traceId。
//
// 上游把定位信息放在 details[] 里（"requestId: xxx" / "traceId: xxx"），丢掉它们
// 等于把用户唯一能反馈给上游的线索丢掉。
func (e errorEnvelope) message() string {
	text := strings.TrimSpace(core.FirstNonEmpty(e.ErrorMsg, e.ErrorMessage, e.Message))
	trace := make([]string, 0, 3)
	if code := strings.TrimSpace(e.ErrorCode); code != "" {
		trace = append(trace, "code="+code)
	}
	for _, detail := range e.Details {
		value := strings.TrimSpace(detail.ErrorMsg)
		index := strings.Index(value, ":")
		if index <= 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(value[:index])) {
		case "requestid", "traceid":
			trace = append(trace, strings.TrimSpace(value[:index])+"="+strings.TrimSpace(value[index+1:]))
		}
	}
	if len(trace) > 0 {
		if text != "" {
			text += " "
		}
		text += "(" + strings.Join(trace, " ") + ")"
	}
	return text
}

// Classify 把 CodeArts 的上游响应分类成共享的上游错误。
func Classify(status int, body string) *core.Failure {
	var envelope errorEnvelope
	_ = json.Unmarshal([]byte(body), &envelope)

	code := core.FirstNonEmpty(envelope.ErrorCode, envelope.errorField())
	msg := core.FirstNonEmpty(envelope.ErrorMsg, envelope.ErrorMessage, envelope.Message,
		envelope.errorField(), body)
	if envelope.carriesError() {
		// 信封里的正文更精确：error_msg 原文 + details 里的 requestId / traceId。
		msg = envelope.message()
	}
	if strings.TrimSpace(msg) == "" {
		// 上游 500 有时连 body 都没有：空正文会让用户看到一条没有任何信息的错误。
		msg = http.StatusText(status)
	}
	return classifyFailure(status, code, msg, false)
}

// ErrorFromPayload 识别 HTTP 200 响应体 / SSE data: 帧里的业务错误信封。
//
// 返回的 Failure 不带 Status：这条错误发生在「传输成功」的响应里，状态码由
// 分类推导（见 core.Failure.HTTPStatus），而不是照抄上游的 200。
func ErrorFromPayload(payload []byte) (*core.Failure, bool) {
	var envelope errorEnvelope
	if errUnmarshal := json.Unmarshal(payload, &envelope); errUnmarshal != nil {
		return nil, false
	}
	if !envelope.carriesError() {
		return nil, false
	}
	return classifyFailure(0, strings.TrimSpace(envelope.ErrorCode), envelope.message(), true), true
}

// OpenAIErrorFrame 把业务错误翻成 OpenAI 错误帧。
//
// 宿主只认 {"error":{"message":...}} 形态的终止帧（见宿主 chunkTerminalError）：
// 认不出上游帧时它会用「流提前结束」覆盖真实原因，这正是 issue #58 的现象。
func OpenAIErrorFrame(failure *core.Failure) ([]byte, error) {
	failure = dialogueFailure(failure)
	return json.Marshal(map[string]any{
		"error": map[string]any{
			"message": failure.Msg,
			"type":    "upstream_error",
			"code":    failure.Code,
		},
	})
}

// classifyFailure 归纳 (status, code, msg) → Failure。
//
// payloadErr 表示错误出现在 200 包体/帧里（status 传 0）：这类错误的处置要按
// 「这条请求/这个模型不可用」来判，不能照搬 HTTP 状态码规则。
func classifyFailure(status int, code, msg string, payloadErr bool) *core.Failure {
	switch {
	case isRefreshTokenInvalid(code, msg):
		// refresh_token 失效是**登录态**问题，不是请求参数问题：状态码是 400，
		// 但按客户端错误归类会让控制台把「账号要重新登录」显示成「参数写错了」。
		return &core.Failure{
			Kind: core.FailureKindCredential, Status: status, Code: code,
			Msg: msg + " — " + refreshTokenInvalidHint,
		}
	case isSecurityTokenExpired(code, msg):
		// STS security token 过期是**可续期**的凭证问题：refresh_token 能换一套
		// 新凭据。状态按 401 归一，宿主的保活重试才会先刷新再重查，而不是把
		// 账号直接标成不可用。
		return &core.Failure{Kind: core.FailureKindCredential, Status: http.StatusUnauthorized, Code: code, Msg: msg}
	case status == http.StatusUnauthorized || status == http.StatusForbidden ||
		strings.Contains(code, "ExpiredToken") || strings.Contains(code, "InvalidToken"):
		return &core.Failure{Kind: core.FailureKindCredential, Status: status, Code: code, Msg: msg}
	case isBenefitMissing(code, msg):
		if payloadErr {
			// 该账号对这个模型没有免费福利：换模型或换账号即可，凭证本身没坏。
			// 归到 model_blocked（可重试、404）而不是 credential——401 会让宿主
			// 直接禁用凭证，把「某个模型不可用」升级成「账号失效」。
			return &core.Failure{Kind: core.FailureKindModelBlocked, Code: code, Msg: msg}
		}
		return &core.Failure{Kind: core.FailureKindCredential, Status: status, Code: code, Msg: msg}
	case status == http.StatusTooManyRequests || strings.Contains(code, "Throttling"):
		return &core.Failure{Kind: core.FailureKindRateLimit, Status: status, Code: code, Msg: msg}
	case status >= 500:
		return &core.Failure{Kind: core.FailureKindTransient, Status: status, Code: code, Msg: msg}
	default:
		return &core.Failure{Kind: core.FailureKindClient, Status: status, Code: code, Msg: msg}
	}
}

// dialogueFailure 只为对话错误追加操作指引；管理页刚执行完签到时不重复催领。
func dialogueFailure(failure *core.Failure) *core.Failure {
	if !isBenefitMissing(failure.Code, failure.Msg) {
		return failure
	}
	copy := *failure
	copy.Msg = withBenefitHint(copy.Msg)
	return &copy
}

// isSecurityTokenExpired 判断是否为华为云 STS 临时凭据过期。
//
// 网关对这种过期的状态码是 400（不是 401），错误码 APIG.0602、正文
// "the security token has expired"。只按状态码分类会把它当成客户端参数错误，
// 于是额度查询与签到永远拿不到重试机会。
func isSecurityTokenExpired(code, msg string) bool {
	if strings.Contains(code, "APIG.0602") {
		return true
	}
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "security token has expired") ||
		strings.Contains(lower, "securitytoken has expired")
}

// isRefreshTokenInvalid 判断是否为「refresh_token 失效」。
//
// 上游对失效的 refresh_token 回 400 + STS5.1804（已过期）/ STS5.1806（已被
// 使用），OAuth 形状的网关回 invalid_grant。这三种都只有重新登录能恢复。
func isRefreshTokenInvalid(code, msg string) bool {
	switch {
	case strings.Contains(code, "STS5.1804"), strings.Contains(code, "STS5.1806"),
		strings.Contains(code, "invalid_grant"):
		return true
	}
	// 少数网关不下发业务码，只有正文。正文必须带判定词才算失效：
	// 「refresh token is required」是参数错误，说成「要重新登录」会把用户
	// 引去一个解决不了问题的方向。
	lower := strings.ToLower(msg)
	if !strings.Contains(lower, "refresh token") {
		return false
	}
	for _, marker := range []string{"invalid", "expired", "has been used", "has expired", "revoked"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// isBenefitMissing 判断是否为「账号没有该模型的免费福利」。
func isBenefitMissing(code, msg string) bool {
	return strings.Contains(code, benefitCodeMarker) ||
		strings.Contains(strings.ToLower(msg), benefitMsgMarker)
}

// withBenefitHint 保留上游原文（含 requestId / traceId），再补一句可操作提示。
func withBenefitHint(msg string) string {
	msg = strings.TrimSpace(msg)
	if strings.Contains(msg, benefitHint) {
		return msg
	}
	if msg == "" {
		return benefitHint
	}
	return msg + " — " + benefitHint
}
