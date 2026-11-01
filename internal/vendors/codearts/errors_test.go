package codearts

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"freetier2api-plugin/internal/core"
)

// streamErrorFrame 是 issue #58 里上游用 HTTP 200 的 data: 帧返回的业务错误。
// 只把 requestId / traceId 换成了合成值，结构与上游原文一致。
const streamErrorFrame = `{"error_code":"InferHub.4004.200","error_msg":"benefit not found","details":[` +
	`{"error_code":"InferHub.4004.200","error_msg":"requestId: req-fixture-0001"},` +
	`{"error_code":"InferHub.4004.200","error_msg":"timestamps: 202610291647"},` +
	`{"error_code":"InferHub.4004.200","error_msg":"modelId: codearts-glm-5.3"},` +
	`{"error_code":"InferHub.4004.200","error_msg":"traceId: trace-fixture-0001"}]}`

// TestErrorFromPayloadKeepsUpstreamTrace 锁定 200 包体/帧里业务错误的识别与原文保留。
//
// 上游把 requestId / traceId 埋在 details[] 里：丢掉它们，用户就没有任何可反馈
// 给上游的线索；而分类若落到 credential，宿主会直接禁用凭证。
func TestErrorFromPayloadKeepsUpstreamTrace(t *testing.T) {
	failure, okFailure := ErrorFromPayload([]byte(streamErrorFrame))
	if !okFailure {
		t.Fatal("error_code/error_msg 信封必须被识别为业务错误")
	}
	if failure.Kind != core.FailureKindModelBlocked {
		t.Fatalf("kind = %s, want model_blocked（换模型/换号即可，不能判成凭证失效）", failure.Kind)
	}
	if failure.Code != "InferHub.4004.200" {
		t.Fatalf("code = %q, want InferHub.4004.200", failure.Code)
	}
	for _, want := range []string{"benefit not found", "requestId=req-fixture-0001",
		"traceId=trace-fixture-0001", "code=InferHub.4004.200"} {
		if !strings.Contains(failure.Msg, want) {
			t.Fatalf("message 缺少 %q: %s", want, failure.Msg)
		}
	}
	if strings.Contains(failure.Msg, benefitHint) {
		t.Fatal("分类层不应把对话操作指引带进管理端签到结果")
	}
}

// TestErrorFromPayloadIgnoresNormalFrames 验证合法帧不会被误判成错误。
func TestErrorFromPayloadIgnoresNormalFrames(t *testing.T) {
	for _, payload := range []string{
		`{"error":{"message":"host generated error","type":"server_error"}}`,
		`{"choices":[{"index":0,"delta":{"content":"hi"}}]}`,
		`{"error_code":"","error_msg":""}`,
		`not json`,
	} {
		if _, okFailure := ErrorFromPayload([]byte(payload)); okFailure {
			t.Fatalf("不该识别为业务错误: %s", payload)
		}
	}
}

// TestClassifyHTTPEnvelopeKeepsTrace 验证 HTTP 错误体同样按信封解析。
func TestClassifyHTTPEnvelopeKeepsTrace(t *testing.T) {
	failure := Classify(http.StatusForbidden, streamErrorFrame)
	if failure.Kind != core.FailureKindCredential {
		t.Fatalf("kind = %s, want credential（HTTP 403 的处置沿用原规则）", failure.Kind)
	}
	if !strings.Contains(failure.Msg, "requestId=req-fixture-0001") {
		t.Fatalf("HTTP 错误体也要保留 requestId: %s", failure.Msg)
	}
}

// TestClassifyEmptyBodyIsReadable 验证上游 500 无正文时也有可读原因。
func TestClassifyEmptyBodyIsReadable(t *testing.T) {
	failure := Classify(http.StatusInternalServerError, "")
	if failure.Kind != core.FailureKindTransient || failure.Msg != http.StatusText(http.StatusInternalServerError) {
		t.Fatalf("failure = %+v, want transient + readable status text", failure)
	}
}

// TestOpenAIErrorFrame 锁定错误帧形态：宿主只认 {"error":{"message":...}}。
func TestOpenAIErrorFrame(t *testing.T) {
	failure, okFailure := ErrorFromPayload([]byte(streamErrorFrame))
	if !okFailure {
		t.Fatal("fixture 必须是可识别的业务错误")
	}
	frame, errFrame := OpenAIErrorFrame(failure)
	if errFrame != nil {
		t.Fatalf("marshal error frame: %v", errFrame)
	}
	var payload struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if errUnmarshal := json.Unmarshal(frame, &payload); errUnmarshal != nil {
		t.Fatalf("decode error frame: %v (%s)", errUnmarshal, frame)
	}
	if !strings.Contains(payload.Error.Message, "benefit not found") {
		t.Fatalf("message 必须保留上游原文: %s", payload.Error.Message)
	}
	if !strings.Contains(payload.Error.Message, benefitHint) || strings.Contains(failure.Msg, benefitHint) {
		t.Fatal("对话帧应追加指引且不修改原始分类错误")
	}
	if payload.Error.Type != "upstream_error" || payload.Error.Code != "InferHub.4004.200" {
		t.Fatalf("error frame = %+v", payload.Error)
	}
}

// TestClassifySnapErrors 锁住 snap 网关错误的分类：正文原因要保留，STS 过期
// 必须归成可续期的凭证错误（状态 401），宿主的保活重试才会触发。
func TestClassifySnapErrors(t *testing.T) {
	signature := Classify(400, `{"error_code":"APIG.0301","error_msg":"verify ak sk signature fail"}`)
	if !strings.Contains(signature.Msg, "APIG.0301") || !strings.Contains(signature.Msg, "signature fail") {
		t.Fatalf("签名错误正文丢失: %q", signature.Msg)
	}

	expired := Classify(400, `{"error_code":"APIG.0602","error_msg":"Bad request: the security token has expired"}`)
	if expired.Kind != core.FailureKindCredential || expired.HTTPStatus() != http.StatusUnauthorized {
		t.Fatalf("STS 过期应归为 401 凭证错误: kind=%v status=%d", expired.Kind, expired.HTTPStatus())
	}
}

// TestClassifyRefreshTokenInvalid 锁住 refresh_token 失效的分类。
//
// 华为云 STS 的 refresh_token 是「单次使用 + 轮转」的：用一次就作废。
// 上游对这种失效回 HTTP 400 + STS5.1806（已被使用）/ STS5.1804（已过期），
// OAuth 形状的网关回 invalid_grant。三者都只有重新登录能恢复——若按 400
// 归成客户端错误，用户会看到「参数写错了」，直到额度一直刷不出来才发现
// 真相。分类为凭据错误并明确提示重新登录。
func TestClassifyRefreshTokenInvalid(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"refresh_token 已被使用", http.StatusBadRequest,
			`{"error_code":"STS5.1806","error_msg":"invalid refresh token: 'the refresh token has been used'"}`},
		{"refresh_token 已过期", http.StatusBadRequest,
			`{"error_code":"STS5.1804","error_msg":"the refresh token has expired"}`},
		{"invalid_grant", http.StatusBadRequest,
			`{"error":"invalid_grant","error_description":"refresh token expired"}`},
	}
	for _, c := range cases {
		failure := Classify(c.status, c.body)
		if failure.Kind != core.FailureKindCredential {
			t.Fatalf("%s: kind = %s, want credential", c.name, failure.Kind)
		}
		if !strings.Contains(failure.Msg, "请重新登录 CodeArts") {
			t.Fatalf("%s: 缺少重新登录提示: %s", c.name, failure.Msg)
		}
	}
}
