package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"freetier2api-plugin/cpasdk/pluginapi"
)

// 额度查询的两处重试：凭证保活（401）与传输层故障。
//
// 这两条路径都容易写成「重试了，但用的是旧凭证」——单测里第一次请求成功，
// 线上表现为「刷新后仍然 401」。断言调用序列而不只是最终结果。

func TestQueryWithRetryReusesRefreshedCredential(t *testing.T) {
	oldCredential := &Credential{Token: "old"}
	newCredential := &Credential{Token: "new"}

	var tokens []string
	query := func(credential *Credential) (*pluginapi.QuotaFetchResponse, error) {
		tokens = append(tokens, credential.TokenValue())
		switch len(tokens) {
		case 1:
			// 凭证过期：必须先刷新，再用新凭证重查。
			return nil, &Failure{Kind: FailureKindCredential, Status: http.StatusUnauthorized}
		case 2:
			// 紧接着的瞬时故障：重试仍要沿用刷新后的凭证。
			return nil, &Failure{Kind: FailureKindTransient, Status: http.StatusBadGateway}
		default:
			return &pluginapi.QuotaFetchResponse{}, nil
		}
	}
	refreshCalls := 0
	refresh := func() (*Credential, error) {
		refreshCalls++
		return newCredential, nil
	}

	if _, errQuota := QueryWithRetry(context.Background(), query, oldCredential, refresh); errQuota != nil {
		t.Fatalf("QueryWithRetry: %v", errQuota)
	}
	want := []string{"old", "new", "new"}
	if len(tokens) != len(want) {
		t.Fatalf("调用序列 = %v, want %v", tokens, want)
	}
	for index := range want {
		if tokens[index] != want[index] {
			t.Fatalf("调用序列 = %v, want %v", tokens, want)
		}
	}
	if refreshCalls != 1 {
		t.Fatalf("刷新次数 = %d, want 1", refreshCalls)
	}
}

func TestQueryWithRetryRetriesTransientWithoutRefresh(t *testing.T) {
	credential := &Credential{Token: "same"}
	calls := 0
	query := func(*Credential) (*pluginapi.QuotaFetchResponse, error) {
		calls++
		if calls == 1 {
			return nil, &Failure{Kind: FailureKindTransient, Status: http.StatusBadGateway}
		}
		return &pluginapi.QuotaFetchResponse{}, nil
	}
	refreshCalls := 0
	refresh := func() (*Credential, error) {
		refreshCalls++
		return credential, nil
	}

	if _, errQuota := QueryWithRetry(context.Background(), query, credential, refresh); errQuota != nil {
		t.Fatalf("QueryWithRetry: %v", errQuota)
	}
	if calls != 2 {
		t.Fatalf("查询次数 = %d, want 2", calls)
	}
	if refreshCalls != 0 {
		t.Fatalf("瞬时故障不应触发刷新，实际刷新 %d 次", refreshCalls)
	}
}

func TestQueryWithRetryKeepsOriginalErrorWhenRefreshFails(t *testing.T) {
	credential := &Credential{Token: "old"}
	calls := 0
	query := func(*Credential) (*pluginapi.QuotaFetchResponse, error) {
		calls++
		return nil, &Failure{Kind: FailureKindCredential, Status: http.StatusUnauthorized}
	}
	// 刷新失败（返回 nil）时不得用旧凭证再打一次。
	if _, errQuota := QueryWithRetry(context.Background(), query, credential, func() (*Credential, error) { return nil, nil }); errQuota == nil {
		t.Fatal("刷新失败时应保留原错误")
	}
	if calls != 1 {
		t.Fatalf("查询次数 = %d, want 1（不得用旧凭证重试）", calls)
	}
}

// TestIsAuthExpiredOnlyMatches401 锁定「只在 401 时才值得刷新一次」。
//
// 额度查询里任何 4xx/5xx 都触发一次保活是最省事的做法，但代价是上游改版或账号
// 无权限时也会白白多打一次上游，还可能把真正的错误盖住。只认 401。
func TestIsAuthExpiredOnlyMatches401(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"401 插件错误", NewPluginError("upstream_credential", "invalid access token", http.StatusUnauthorized), true},
		{"401 上游分类错误", &Failure{Kind: FailureKindCredential, Status: 401, Msg: "invalid access token"}, true},
		{"403 权限问题", NewPluginError("upstream_credential", "forbidden", http.StatusForbidden), false},
		{"502 上游异常", NewPluginError("upstream_request_failed", "bad gateway", http.StatusBadGateway), false},
		{"非凭证的分类错误", &Failure{Kind: FailureKindServer, Status: 500}, false},
		{"普通错误", errors.New("boom"), false},
		{"被包装的 401", fmt.Errorf("查询失败: %w", NewPluginError("upstream_credential", "expired", http.StatusUnauthorized)), true},
	}
	for _, c := range cases {
		if got := IsAuthExpired(c.err); got != c.want {
			t.Fatalf("%s: IsAuthExpired = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestIsTransientFailureOnlyTrustsClassification 锁定「只按分类重试」。
//
// 按状态码猜（502/503 一律重试）会把上游明确拒绝也当成抖动；分类结果才是
// 唯一依据，供应商要把传输层失败归成 FailureKindTransient。
func TestIsTransientFailureOnlyTrustsClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"transient 分类错误", &Failure{Kind: FailureKindTransient, Status: 502}, true},
		{"被包装的 transient", fmt.Errorf("查询失败: %w", &Failure{Kind: FailureKindTransient}), true},
		{"502 插件错误未分类", NewPluginError("codearts_snap_transport", "snap request failed: EOF", http.StatusBadGateway), false},
		{"503 上游不可用", NewPluginError("upstream_unavailable", "unavailable", http.StatusServiceUnavailable), false},
		{"401 凭证问题", NewPluginError("upstream_credential", "expired", http.StatusUnauthorized), false},
		{"400 参数问题", NewPluginError("upstream_request", "bad request", http.StatusBadRequest), false},
		{"普通错误", errors.New("boom"), false},
	}
	for _, c := range cases {
		if got := IsTransientFailure(c.err); got != c.want {
			t.Fatalf("%s: IsTransientFailure = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestQueryWithRetryReportsRefreshFailure 锁定「自动续期失败」的呈现方式。
//
// 只报原始 401，用户看不出该重新登录还是稍后再试；而用旧凭证再打一次
// 必然得到同一个 401，白白多打一次上游。正确行为是：不重试，把续期失败
// 的原因并进原始错误，同时保留 401 的分类（宿主仍按凭证失效处置）。
func TestQueryWithRetryReportsRefreshFailure(t *testing.T) {
	credential := &Credential{Token: "old"}
	calls := 0
	query := func(*Credential) (*pluginapi.QuotaFetchResponse, error) {
		calls++
		return nil, &Failure{Kind: FailureKindCredential, Status: http.StatusUnauthorized}
	}
	refresh := func() (*Credential, error) {
		return nil, errors.New("refresh_token 已失效，请重新登录 CodeArts")
	}

	_, errQuota := QueryWithRetry(context.Background(), query, credential, refresh)
	if errQuota == nil {
		t.Fatal("续期失败时应返回错误")
	}
	if calls != 1 {
		t.Fatalf("查询次数 = %d, want 1（不得用旧凭证重试）", calls)
	}
	if !strings.Contains(errQuota.Error(), "自动续期失败") ||
		!strings.Contains(errQuota.Error(), "请重新登录 CodeArts") {
		t.Fatalf("错误未带上续期失败原因: %v", errQuota)
	}
	if !IsAuthExpired(errQuota) {
		t.Fatalf("原始 401 的分类必须保留，宿主才能继续按凭证失效处置: %v", errQuota)
	}
}
