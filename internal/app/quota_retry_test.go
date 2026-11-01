package app

// 本文件锁住「宿主额度面板的重试语义」。
//
// handleQuotaFetch 与宿主的 QuotaFetcher 契约直接对接：查不到额度就返回错误，
// 宿主据此决定面板显示真数字还是错误。401 换凭证重试、刷新拿不到新凭证时
// 保留 401、无错时只查一次——这三种结局决定用户看到什么，之前只有 core 层
// 单测，app 层接线没人守（#71 第二轮复审 P2-5）。

import (
	"context"
	"errors"
	"testing"

	"freetier2api-plugin/internal/core"

	"freetier2api-plugin/cpasdk/pluginapi"
)

// fakeQuotaProvider 记录每次调用实际用的凭证，并按序号返回预置结果。
type fakeQuotaProvider struct {
	calls []string
	reply func(call int, credential *core.Credential) (*pluginapi.QuotaFetchResponse, error)
}

func (f *fakeQuotaProvider) Quota(_ context.Context, credential *core.Credential) (*pluginapi.QuotaFetchResponse, error) {
	f.calls = append(f.calls, credential.FileID)
	return f.reply(len(f.calls), credential)
}

// TestQueryVendorQuotaRetriesWithRefreshedCredential 锁住「401 换新凭证重查」。
func TestQueryVendorQuotaRetriesWithRefreshedCredential(t *testing.T) {
	provider := &fakeQuotaProvider{reply: func(call int, credential *core.Credential) (*pluginapi.QuotaFetchResponse, error) {
		if call == 1 {
			return nil, core.NewPluginError("unauthorized", "access token expired", 401)
		}
		if credential.FileID != "new" {
			t.Fatalf("第 %d 次调用用的还是旧凭证 %q", call, credential.FileID)
		}
		return &pluginapi.QuotaFetchResponse{Claim: &pluginapi.ClaimStatus{Available: 1}}, nil
	}}
	response, errQuery := queryVendorQuota(context.Background(),
		&core.Credential{FileID: "old"}, provider,
		func() (*core.Credential, error) { return &core.Credential{FileID: "new"}, nil })
	if errQuery != nil {
		t.Fatalf("换凭证后应当成功，得到错误 %v", errQuery)
	}
	if response == nil || response.Claim == nil {
		t.Fatalf("应当拿到刷新后的响应，得到 %#v", response)
	}
	if len(provider.calls) != 2 || provider.calls[0] != "old" || provider.calls[1] != "new" {
		t.Fatalf("调用序列应为 [old new]，实际 %v", provider.calls)
	}
}

// TestQueryVendorQuotaKeeps401WhenRefreshFails 锁住「刷新拿不到凭证时不重试」。
//
// 拿旧凭证再打一次只会得到同一个 401，还会白耗一次上游配额；错误必须原样
// 上抛，宿主才能把「凭证失效」如实显示出来。
func TestQueryVendorQuotaKeeps401WhenRefreshFails(t *testing.T) {
	provider := &fakeQuotaProvider{reply: func(int, *core.Credential) (*pluginapi.QuotaFetchResponse, error) {
		return nil, core.NewPluginError("unauthorized", "access token expired", 401)
	}}
	_, errQuery := queryVendorQuota(context.Background(),
		&core.Credential{FileID: "old"}, provider,
		func() (*core.Credential, error) { return nil, nil })
	if errQuery == nil {
		t.Fatal("刷新失败时应当把 401 抛出去")
	}
	var pluginErr *core.PluginError
	if !errors.As(errQuery, &pluginErr) || pluginErr.HTTPStatus != 401 {
		t.Fatalf("应当保留原始 401，得到 %#v", errQuery)
	}
	if len(provider.calls) != 1 {
		t.Fatalf("刷新失败时不应重试，实际调用 %v", provider.calls)
	}
}

// TestQueryVendorQuotaCallsOnceOnSuccess 锁住「成功路径不做多余请求」。
func TestQueryVendorQuotaCallsOnceOnSuccess(t *testing.T) {
	provider := &fakeQuotaProvider{reply: func(int, *core.Credential) (*pluginapi.QuotaFetchResponse, error) {
		return &pluginapi.QuotaFetchResponse{}, nil
	}}
	refreshed := 0
	if _, errQuery := queryVendorQuota(context.Background(),
		&core.Credential{FileID: "old"}, provider,
		func() (*core.Credential, error) {
			refreshed++
			return &core.Credential{FileID: "new"}, nil
		}); errQuery != nil {
		t.Fatalf("正常路径不应报错: %v", errQuery)
	}
	if len(provider.calls) != 1 || refreshed != 0 {
		t.Fatalf("正常路径应当只查一次且不刷新，调用 %v，刷新 %d 次", provider.calls, refreshed)
	}
}

// TestQueryVendorQuotaDoesNotRefreshOn403 锁住「403 不触发保活」。
//
// 403 通常是账号没权限或上游改版，刷新换不来权限，只会多打一次上游。
func TestQueryVendorQuotaDoesNotRefreshOn403(t *testing.T) {
	provider := &fakeQuotaProvider{reply: func(int, *core.Credential) (*pluginapi.QuotaFetchResponse, error) {
		return nil, core.NewPluginError("forbidden", "no permission", 403)
	}}
	refreshed := 0
	_, errQuery := queryVendorQuota(context.Background(),
		&core.Credential{FileID: "old"}, provider,
		func() (*core.Credential, error) {
			refreshed++
			return &core.Credential{FileID: "new"}, nil
		})
	if errQuery == nil {
		t.Fatal("403 应当原样上抛")
	}
	if refreshed != 0 || len(provider.calls) != 1 {
		t.Fatalf("403 不应触发刷新/重试，刷新 %d 次、调用 %v", refreshed, provider.calls)
	}
}
