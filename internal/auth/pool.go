// Package auth 统一账号枚举、凭证解析、去重、批量执行与登录会话登记。
//
// admin / tasks / quota / keepalive 都曾各自实现一遍“列 auth → 取 JSON →
// 解析凭证 → 过滤 → 去重”，且去重键不一致。本包把这条链收口一次。
//
// 登录会话（SessionRegistry）也放在这里：它与凭证枚举共享“按 App 实例隔离”
// 的生命周期，供应商只经core.Env.Logins 使用，不需要认识本包。
package auth

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
	"freetier2api-plugin/internal/logger"
)

// Resolver 由根层注入：把原始凭证解析成 (Credential, Vendor)。
type Resolver func(ctx context.Context, callbackID string, storageJSON []byte, authID string, attrs map[string]string) (*core.Credential, core.Vendor, error)

// Pool 是账号枚举与批量解析的入口。
type Pool struct {
	Registry *core.Registry
	Resolve  Resolver
}

// NewPool 构造账号池。
func NewPool(registry *core.Registry, resolve Resolver) *Pool {
	return &Pool{Registry: registry, Resolve: resolve}
}

// Account 是一个已解析的可用账号。
type Account struct {
	Entry      core.HostAuth
	Credential *core.Credential
	Vendor     core.Vendor
	RawJSON    []byte
	FilePath   string
}

// Failure 是一条无法解析的账号记录。
type Failure struct {
	Entry   core.HostAuth
	Message string
}

// Options 控制账号筛选。
//
// EnabledRealms 直接给域列表而不是判定闭包：realm 过滤的语义只有一处实现
// （core.RealmEnabled），调用方不必各自包一层闭包——那正是此前四处重复的来源。
// 留空表示不限制，与 core.RealmEnabled(nil, _) == true 一致。
type Options struct {
	Targets         []string
	Filter          func(Account) bool
	EnabledRealms   []string
	IncludeDisabled bool
}

// Load 返回可用账号与失败条目；按 credential FileID 去重。
func (p *Pool) Load(ctx context.Context, callbackID string, opts Options) ([]Account, []Failure) {
	entries, errList := hostbridge.ListAuths(ctx, callbackID, p.Registry)
	if errList != nil {
		return nil, []Failure{{Message: "读取账号列表失败：" + errList.Error()}}
	}
	wanted := map[string]bool{}
	for _, target := range opts.Targets {
		if trimmed := strings.TrimSpace(target); trimmed != "" {
			wanted[trimmed] = true
		}
	}
	accounts := make([]Account, 0, len(entries))
	failures := make([]Failure, 0)
	seen := map[string]bool{}
	vendorCounts := map[string]int{}
	for _, entry := range entries {
		if !opts.IncludeDisabled && !entry.Usable() {
			continue
		}
		if len(wanted) > 0 && !wanted[entry.ID] && !wanted[entry.Name] && !wanted[entry.AuthIndex] {
			continue
		}
		raw, filePath, okRaw := hostbridge.AuthJSONAndPath(ctx, callbackID, entry.AuthIndex)
		if !okRaw && strings.TrimSpace(entry.Path) != "" {
			if data, errRead := os.ReadFile(entry.Path); errRead == nil && len(data) > 0 {
				raw, filePath, okRaw = data, entry.Path, true
			}
		}
		if !okRaw || len(raw) == 0 {
			failures = append(failures, Failure{Entry: entry, Message: "凭证读取失败"})
			continue
		}
		credential, vendor, errResolve := p.Resolve(ctx, callbackID, raw, hostbridge.AccountIdentity(entry), nil)
		if errResolve != nil {
			failures = append(failures, Failure{Entry: entry, Message: "凭证解析失败: " + errResolve.Error()})
			continue
		}
		if !core.RealmEnabled(opts.EnabledRealms, vendor.Region()) {
			continue
		}
		uid := credential.FileIDValue()
		if uid != "" {
			if seen[uid] {
				continue
			}
			seen[uid] = true
		}
		if vendorCounts[vendor.ID()] >= core.MaxAccountsPerVendor {
			failures = append(failures, Failure{Entry: entry, Message: fmt.Sprintf("超过单供应商 %d 个账号上限", core.MaxAccountsPerVendor)})
			continue
		}
		account := Account{Entry: entry, Credential: credential, Vendor: vendor, RawJSON: raw, FilePath: filePath}
		if opts.Filter != nil && !opts.Filter(account) {
			continue
		}
		vendorCounts[vendor.ID()]++
		accounts = append(accounts, account)
	}
	return accounts, failures
}

// CheckVendorLimit 校验目标供应商是否已达到单供应商账号上限（MaxAccountsPerVendor）。
//
// candidateFileName 非空时，若该文件对应同供应商下已存在的账号（同名覆盖更新），
// 则放行；新增账号在已有数量达到上限时返回 400 PluginError。
func (p *Pool) CheckVendorLimit(ctx context.Context, callbackID string, vendor core.Vendor, candidateFileName string) error {
	if p == nil || vendor == nil {
		return nil
	}
	loaded, _ := p.Load(ctx, callbackID, Options{IncludeDisabled: true})
	candidateID := strings.TrimSuffix(strings.TrimSpace(candidateFileName), ".json")
	count := 0
	for _, account := range loaded {
		if account.Vendor.ID() != vendor.ID() {
			continue
		}
		if candidateID != "" && (account.Credential.FileIDValue() == candidateID ||
			strings.TrimSuffix(strings.TrimSpace(account.Entry.Name), ".json") == candidateID ||
			strings.TrimSuffix(strings.TrimSpace(account.Entry.ID), ".json") == candidateID) {
			return nil
		}
		count++
	}
	if count >= core.MaxAccountsPerVendor {
		return core.NewPluginError("account_limit_exceeded",
			fmt.Sprintf("每个供应商最多添加 %d 个账号（%s 已达上限）", core.MaxAccountsPerVendor, vendor.Name()),
			http.StatusBadRequest)
	}
	return nil
}

// RefreshCredential 保活刷新后从账号池重新取回该账号的凭证。
//
// 额度查询（app 侧）与控制台刷新（admin 侧）共用这一段：先跑 keepalive
// （供应商在这里完成 refresh token → access token 的交换并写回宿主存储），
// 再从账号池重新加载取到新凭证。两处各写一遍时，任一处忘了重新加载就会拿着
// 旧凭证重试，401 原样再挂一次。
//
// 返回值有两个含义，缺一不可：
//   - 凭证非 nil：续期成功，调用方用它重试；
//   - 错误非 nil：续期没成功，错误里是**原因**（例如「refresh_token 已被使用
//     过，请重新登录」）。调用方要把它并进原始 401，否则用户只看到一句
//     「凭证已过期」，既不知道该重新登录还是稍后再试，也只能反复点刷新。
//
// 两者都为 nil 表示「没能拿到新凭证但不致命」（如账号已不存在）：调用方
// 保留原 401 如实上报——不要在 nil 上继续拼请求，也不要把「刷新失败」当成
// 「额度为 0」。
func RefreshCredential(ctx context.Context, pool *Pool, callbackID, authID, vendorID string, realms []string, keepalive func() error) (*core.Credential, error) {
	if pool == nil || authID == "" || vendorID == "" {
		return nil, nil
	}
	if keepalive != nil {
		if errKeepalive := keepalive(); errKeepalive != nil {
			return nil, errKeepalive
		}
	}
	// Load 的失败条目都对应本次的目标账号（Pool.Load 先按 Targets 过滤）。
	loaded, failures := pool.Load(ctx, callbackID, Options{Targets: []string{authID}, EnabledRealms: realms})
	if len(failures) > 0 {
		// 加载失败与「刷新后仍然找不到」表现相同（都拿不到凭证），不记一笔的话
		// 凭证服务真挂了，排查时只能看到「凭证缺失」（#71 第二轮复审 P2-6）。
		logger.Debug("刷新后重新加载凭证失败 auth=%s vendor=%s: %s", authID, vendorID, failures[0].Message)
		return nil, fmt.Errorf("刷新后重新加载凭证失败: %s", failures[0].Message)
	}
	for _, account := range loaded {
		if account.Vendor != nil && account.Vendor.ID() == vendorID {
			return account.Credential, nil
		}
	}
	return nil, nil
}
