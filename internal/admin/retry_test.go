package admin

import (
	"net/http"
	"testing"

	"freetier2api-plugin/internal/core"
)

// 批量动作的凭证保活重试。额度查询那条已随实现下沉到 core/retry_test.go。

func TestRunWithAuthRetryOnlyOn401(t *testing.T) {
	oldCredential := &core.Credential{Token: "old"}
	newCredential := &core.Credential{Token: "new"}

	refreshCalls := 0
	actionCalls := 0
	outcome, errAction := runWithAuthRetry(oldCredential, func() (*core.Credential, error) {
		refreshCalls++
		return newCredential, nil
	}, func(credential *core.Credential) (accountActionOutcome, error) {
		actionCalls++
		if actionCalls == 1 {
			return accountActionOutcome{}, &core.Failure{Kind: core.FailureKindCredential, Status: http.StatusUnauthorized}
		}
		if credential.TokenValue() != "new" {
			t.Fatalf("重试必须使用刷新后的凭证，实际 %q", credential.TokenValue())
		}
		return accountActionOutcome{Message: "ok"}, nil
	})
	if errAction != nil || outcome.Message != "ok" {
		t.Fatalf("重试后应成功: outcome=%+v err=%v", outcome, errAction)
	}
	if refreshCalls != 1 || actionCalls != 2 {
		t.Fatalf("刷新 %d 次 / 动作 %d 次, want 1 / 2", refreshCalls, actionCalls)
	}

	// 非 401（参数错误）不刷新：刷新不会变好，只会多打一次上游。
	refreshCalls = 0
	_, _ = runWithAuthRetry(oldCredential, func() (*core.Credential, error) {
		refreshCalls++
		return newCredential, nil
	}, func(*core.Credential) (accountActionOutcome, error) {
		return accountActionOutcome{}, &core.Failure{Kind: core.FailureKindBadParams, Status: http.StatusBadRequest}
	})
	if refreshCalls != 0 {
		t.Fatalf("400 不应触发刷新，实际刷新 %d 次", refreshCalls)
	}
}
