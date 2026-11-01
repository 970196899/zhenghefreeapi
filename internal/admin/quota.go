package admin

import (
	"context"
	"net/http"
	"time"

	"freetier2api-plugin/cpasdk/pluginapi"
	accountpkg "freetier2api-plugin/internal/auth"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
	"freetier2api-plugin/internal/state"
)

// quotaJob 是额度查询里的一个账号任务。
type quotaJob struct {
	entry      core.HostAuth
	vendor     core.Vendor
	credential *core.Credential
}

// identity 返回该任务的账号身份字段（结果与缓存共用）。
func (j quotaJob) identity() quotaResult {
	return quotaResult{
		AuthID:     core.FirstNonEmpty(j.entry.ID, j.entry.Name),
		AuthIndex:  j.entry.AuthIndex,
		Name:       j.entry.Name,
		UID:        j.credential.FileIDValue(),
		Label:      core.FirstNonEmpty(j.credential.LabelValue(), j.entry.Label, j.entry.Name),
		VendorID:   j.vendor.ID(),
		VendorName: j.vendor.Name(),
		Realm:      j.credential.RegionValue(),
	}
}

// quotaResult 是单个账号的额度结果。
type quotaResult struct {
	AuthID     string `json:"auth_id"`
	AuthIndex  string `json:"auth_index,omitempty"`
	Name       string `json:"name,omitempty"`
	UID        string `json:"uid,omitempty"`
	Label      string `json:"label"`
	VendorID   string `json:"vendor_id,omitempty"`
	VendorName string `json:"vendor_name,omitempty"`
	Realm      string `json:"realm"`
	OK         bool   `json:"ok"`
	Message    string `json:"message,omitempty"`
	Summary    string `json:"summary,omitempty"`
	Remain     int64  `json:"remain"`
	Total      int64  `json:"total"`
	// HasTotal 报告上游是否真的报了总额。
	//
	// 多数渠道（AutoClaw、Raccoon、MiniMax 等）只给余额不给总额；此时 Total
	// 是 0 而不是「总额为 0」，展示层必须据此显示「余额 / —」。
	//
	// 反过来，HasTotal 为真也不代表 Total 大于 0：CodeArts 未开通福利、Qoder
	// 的 0/0 桶都会给出 total=0。展示层算百分比时必须同时校验 Total > 0，
	// 否则 0/0 会渲染成 NaN%（见 #71 第二轮复审 P1-1）。
	HasTotal bool `json:"has_total,omitempty"`
	// Unlimited 报告剩余额度无上限，展示层据此显示「无限」。
	Unlimited bool                    `json:"unlimited,omitempty"`
	Metrics   []pluginapi.QuotaMetric `json:"metrics,omitempty"`
	// Stale 标记这份读数是上次成功取到的结果，本次刷新失败。
	//
	// 上游限流/超时/5xx 是常态：失败时把额度列清空，用户分不清「没额度了」和
	// 「这次没取到」。保留上次读数并标非实时，比给一个空白更有信息量。
	Stale bool `json:"stale,omitempty"`
	// StaleReason 是本次刷新失败的原因（Stale 为 true 时才有）。
	StaleReason string `json:"stale_reason,omitempty"`
	// FetchedAt 是这份读数的实际获取时间（RFC3339）。
	FetchedAt string `json:"fetched_at,omitempty"`
}

// claimNote 给「有领取状态但没有额度明细」的账号补一句说明。
//
// 上游在活动套餐生效前不会生成额度桶：此时 Claim 显示「已领取」，额度却是
// 空的。不解释一句，页面看上去像取数失败。文案由这里统一生成，而不是让每个
// 供应商自己拼——说明属于展示层，宿主契约里不该出现插件专用字段。
//
// 只陈述能从契约字段推出的事实：这里拿不到套餐到期时间，所以不说「已过期」
// ——把「不知道」说成「过期」比不说更糟。
func claimNote(claim *pluginapi.ClaimStatus, result quotaResult) string {
	if claim == nil || claim.Error != "" {
		return ""
	}
	// 额度本身没查到就别编说明：额度列已经写着失败原因，这里再说一句「上游
	// 暂未返回明细」，会让人以为是活动还没生效，而不是这次取数根本没成功。
	//
	// 防御性检查：生产路径下 outcome.claim 仅在额度查询成功后赋值，此时 result.OK
	// 必然为 true；此处保留守卫，防止未来重构调用链路时误把失败态传入。
	if !result.OK {
		return ""
	}
	if len(result.Metrics) > 0 || (result.HasTotal && result.Total > 0) {
		return ""
	}
	if claim.Claimable > 0 {
		return "有可领取的套餐，领取后才会生成额度"
	}
	return "已领取，上游暂未返回额度明细"
}

// quotaBatchOutcome 是一轮批量查询里单个账号的产出。
//
// 领取状态与额度结果分开携带：额度结果会进缓存并被多次读，领取状态只在
// 批末统一落盘一次，两者生命周期不同。
type quotaBatchOutcome struct {
	result quotaResult
	claim  *pluginapi.ClaimStatus
}

func (s *Service) handleQuotasRequest(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	body, errDecode := decodeRequest[accountBatchRequest](req.Body)
	if errDecode != nil {
		return BadJSONRequestResponse()
	}
	ctx, cancel := hostbridge.ManagementContext(req, requestTimeout)
	defer cancel()
	callbackID := hostbridge.RequestCallbackID(req)

	cfg := s.deps.Config()
	loaded, failures := s.pool.Load(ctx, callbackID, accountpkg.Options{
		Targets:       body.AccountIDs,
		EnabledRealms: cfg.EnabledRealms,
	})
	results := make([]quotaResult, 0, len(failures)+len(loaded))
	for _, failure := range failures {
		results = append(results, quotaResult{
			AuthID:  core.FirstNonEmpty(failure.Entry.ID, failure.Entry.Name),
			Label:   core.FirstNonEmpty(failure.Entry.Label, failure.Entry.Name, failure.Entry.ID),
			Message: failure.Message,
		})
	}
	if len(loaded) == 0 {
		return JSONResponse(http.StatusOK, map[string]any{"ok": true, "results": results})
	}

	// 查询跑在**后台作用域**（空 callback ID + 独立超时），不跟随本次管理 RPC：
	// 页面刷新/关闭会让宿主取消这条 RPC，若查询挂在它的 context 上，这一轮
	// 一个账号都写不进缓存，账号表就只能显示「查询中…」。
	// 已有一轮在跑时不重复打上游：等它结束，再回读缓存。
	jobs := make([]quotaJob, 0, len(loaded))
	for _, account := range loaded {
		job := quotaJob{entry: account.Entry, vendor: account.Vendor, credential: account.Credential}
		// 不支持额度查询的供应商（如 OpenCode ZEN）不进查询轮次、不写缓存，
		// 也不进 /quotas 结果——页面据 /status 的 supports_quota=false 直接显示
		// 「-- / --」，不需要一条注定失败的结果。
		if !supportsQuota(account.Vendor) {
			continue
		}
		jobs = append(jobs, job)
	}
	if len(jobs) == 0 {
		// 全是失败项或不支持额度的账号：没有要跑的一轮，直接回结果。
		return JSONResponse(http.StatusOK, map[string]any{"ok": true, "results": results})
	}
	done, owner := s.acquireQuotaRun()
	if owner {
		go s.runQuotaBatch(done, jobs)
	}
	select {
	case <-done:
	case <-ctx.Done():
		// 页面已走开：不阻塞后台那一轮，直接回当前缓存（可能只完成了一部分）。
	}

	for _, job := range jobs {
		identity := job.identity()
		if cached := s.getCachedQuota(identity.VendorID, identity.UID, identity.AuthID); cached != nil {
			results = append(results, *cached)
			continue
		}
		identity.Message = "额度查询尚未完成，请稍后刷新"
		results = append(results, identity)
	}
	return JSONResponse(http.StatusOK, map[string]any{"ok": true, "results": results})
}

// acquireQuotaRun 取得「额度查询轮次」的执行权。
//
// 返回本轮完成信号与是否为发起者。已有一轮在跑时返回它的完成信号，
// 调用方等同一轮结束即可，避免刷新页面时把同一批账号重复打向上游。
func (s *Service) acquireQuotaRun() (chan struct{}, bool) {
	s.quotaRunMu.Lock()
	defer s.quotaRunMu.Unlock()
	if s.quotaRun != nil {
		return s.quotaRun, false
	}
	s.quotaRun = make(chan struct{})
	return s.quotaRun, true
}

// finishQuotaRun 结束本轮：先关完成信号，再交出执行权。
func (s *Service) finishQuotaRun(done chan struct{}) {
	s.quotaRunMu.Lock()
	if s.quotaRun == done {
		s.quotaRun = nil
	}
	s.quotaRunMu.Unlock()
	close(done)
}

// runQuotaBatch 在后台作用域里查询全部账号额度，逐个写缓存。
//
// 每个账号完成即写缓存（成功与失败都写），因此页面在轮次中途刷新也能
// 看到已完成的账号，而不是整批退回「查询中」。
func (s *Service) runQuotaBatch(done chan struct{}, jobs []quotaJob) {
	defer s.finishQuotaRun(done)

	ctx, cancel := context.WithTimeout(hostbridge.WithCallbackID(context.Background(), ""), requestTimeout)
	defer cancel()

	outcomes := accountpkg.RunBatch(jobs, batchConcurrency, func(current quotaJob) (outcome quotaBatchOutcome) {
		outcome.result = current.identity()
		// **成功与失败都要缓存**：缓存是账号表唯一的数据源。只缓存成功结果会让
		// 失败账号在下次 /status 时退回「没有结果」，页面于是永远停在「查询中…」——
		// 而「上游没有额度接口」这类结论早已确定，不存在还会变。
		defer func() {
			result := outcome.result
			// 失败时保留的上次读数不写回缓存：缓存要保持「最后一次成功」，
			// 否则 Stale 标记会一直粘着，下次成功前页面永远显示非实时。
			if result.Stale {
				return
			}
			s.cacheQuotaResult(result)
		}()
		quota, errQuota := s.queryQuota(ctx, current)
		if errQuota != nil {
			identity := current.identity()
			if kept, okKept := keepLastQuota(s.getCachedQuota(identity.VendorID, identity.UID, identity.AuthID), errQuota); okKept {
				// 有上次成功读数：返回它并标非实时，附上本次失败原因。
				outcome.result = kept
				return outcome
			}
			outcome.result.Message = errQuota.Error()
			return outcome
		}
		result := &outcome.result
		if quota.Claim != nil {
			outcome.claim = quota.Claim
		}
		result.OK = true
		result.Stale = false
		result.StaleReason = ""
		result.FetchedAt = time.Now().Format(time.RFC3339)
		result.Summary = accountpkg.Summary(quota)
		totals := accountpkg.Totals(quota)
		result.Remain, result.Total, result.Unlimited = totals.Remaining, totals.Total, totals.Unlimited
		result.HasTotal = totals.HasTotal
		result.Metrics = quota.Summary
		return outcome
	})

	// 领取状态跟着额度一起刷新，但**批末才落盘**：Mutate 每次都会写一遍
	// state.json，逐账号写等于把一次「查询额度」放大成 N 次磁盘写。
	claims := map[string]state.ClaimRecord{}
	for _, outcome := range outcomes {
		if outcome.claim != nil {
			claims[outcome.result.UID] = state.ClaimRecord{
				ClaimStatus: *outcome.claim,
				Note:        claimNote(outcome.claim, outcome.result),
				CheckedAt:   time.Now().Format(time.RFC3339),
			}
		}
	}
	if len(claims) > 0 {
		s.deps.MutateState(func(current *state.State) {
			for uid, record := range claims {
				current.Claim[uid] = record
			}
		})
	}
}

// keepLastQuota 把「本次刷新失败」折算成「上次成功读数 + 非实时标记」。
//
// 上游限流（429）、超时、5xx 是常态而非异常：失败时把额度列清空，用户分不清
// 「没额度了」和「这次没取到」。保留上次读数并标非实时，比给一个空白更有
// 信息量。没有上次成功读数时返回 false，调用方退回报错。
func keepLastQuota(previous *quotaResult, errQuota error) (quotaResult, bool) {
	if previous == nil || !previous.OK || errQuota == nil {
		return quotaResult{}, false
	}
	// 确定类失败不能拿旧读数顶：硬额度耗尽、凭证失效、内容拦截这些不会自己
	// 好转，保留上次的正常读数等于把「额度已经没了」显示成还有额度。只有
	// 限流/超时/5xx 这类过一会儿就能恢复的失败才走「上次读数 + 非实时」。
	if core.IsDefinitiveFailure(errQuota) {
		return quotaResult{}, false
	}
	kept := *previous
	kept.Stale = true
	kept.StaleReason = errQuota.Error()
	return kept, true
}

// queryQuota 查询单个账号的额度（含一次过期凭证的保活重试）。
//
// 只负责取数；缓存、领取状态落盘由 runQuotaBatch 统一负责。
func (s *Service) queryQuota(ctx context.Context, job quotaJob) (*pluginapi.QuotaFetchResponse, error) {
	quotaProvider, okQuota := core.As[core.QuotaProvider](job.vendor)
	if !okQuota {
		return nil, core.QuotaUnsupported(job.vendor)
	}
	return core.QueryWithRetry(ctx,
		func(credential *core.Credential) (*pluginapi.QuotaFetchResponse, error) {
			return quotaProvider.Quota(ctx, credential)
		},
		job.credential,
		func() (*core.Credential, error) {
			return s.refreshedCredential(ctx, "", job.entry, job.vendor)
		},
	)
}

// refreshedCredential 在额度查询遇到 401 时保活刷新一次凭证。
//
// 与宿主额度路由（app.refreshedQuotaCredential）同源，实现见
// accountpkg.RefreshCredential。续期失败时把原因一并返回：调用方要把它
// 并进原始 401，用户才能知道该重新登录还是稍后再试。
func (s *Service) refreshedCredential(ctx context.Context, callbackID string, entry core.HostAuth, vendor core.Vendor) (*core.Credential, error) {
	if vendor == nil {
		return nil, nil
	}
	authID := core.FirstNonEmpty(entry.ID, entry.Name)
	return accountpkg.RefreshCredential(ctx, s.pool, callbackID, authID, vendor.ID(), s.deps.Config().EnabledRealms,
		func() error { return s.tasks.KeepaliveError(ctx, callbackID, authID) })
}
