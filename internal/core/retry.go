package core

// 本文件是「上游调用重试」的唯一实现：凭证过期保活一次、传输层故障等待后
// 重试一次。控制台额度面板与宿主额度面板都必须走这里。
//
// 之所以要下沉到 core：宿主面板（app.handleQuotaFetch）与控制台
// （admin.queryQuota）查询的是同一批上游、同一批凭证，但此前只有控制台
// 做了保活与重试，宿主面板直接单发一次——MiniMax 的 access token 只有
// 1 小时有效期，于是「控制台刷新成功、宿主面板 401」这种分裂会周期性出现。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// QuotaRetryDelay 是瞬时故障重试前的等待。
const QuotaRetryDelay = 500 * time.Millisecond

// RefreshFunc 是一次凭证续期。
//
// 返回新凭证即视为续期成功；返回错误即续期失败，调用方要把失败原因并进
// 原始错误——只报「凭证已过期」而不报「自动续期也没成功」，用户既看不出
// 该重新登录还是稍后再试，也只能反复点刷新。
type RefreshFunc func() (*Credential, error)

// QueryWithRetry 执行一次上游查询并处理两种重试。
//
//   - 凭证过期（401）：先保活刷新一次，用新凭证重查。MiniMax 的 access token
//     只有 1 小时有效期，不刷新的话额度列会一直挂着 401。
//   - 传输层故障（transient）：上游 EOF / 连接重置在实测里成片出现，等待后
//     重查一次；重试必须沿用刷新后的凭证，否则会把新 token 换回旧的再打一次 401。
//
// 拆成泛型函数是为了可测：真实依赖（保活、账号池）由调用方注入。
func QueryWithRetry[T any](
	ctx context.Context,
	query func(*Credential) (T, error),
	credential *Credential,
	refresh RefreshFunc,
) (T, error) {
	result, used, errQuery := WithAuthRetry(credential, refresh, query)
	if errQuery != nil && IsTransientFailure(errQuery) && SleepContext(ctx, QuotaRetryDelay) {
		result, errQuery = query(used)
	}
	return result, errQuery
}

// WithAuthRetry 在动作因凭证过期（401）失败时刷新一次凭证再重试。
//
// 返回最终结果、实际使用的凭证（重试时是刷新后的）与错误。刷新失败时保留原
// 错误、不重试：用旧凭证再打一次只会得到同一个 401；失败原因用
// AuthRetryError 并进原始错误，让用户看到「续期也没成功」。
func WithAuthRetry[T any](
	credential *Credential,
	refresh RefreshFunc,
	action func(*Credential) (T, error),
) (T, *Credential, error) {
	result, errAction := action(credential)
	if errAction == nil || !IsAuthExpired(errAction) || refresh == nil {
		return result, credential, errAction
	}
	refreshed, errRefresh := refresh()
	if errRefresh != nil {
		return result, credential, AuthRetryError(errAction, errRefresh)
	}
	if refreshed == nil {
		return result, credential, errAction
	}
	result, errAction = action(refreshed)
	return result, refreshed, errAction
}

// AuthRetryError 把「凭证已过期」与「自动续期失败的原因」并成一条错误。
//
// 原始错误用 %w 保留：分类（IsAuthExpired / IsDefinitiveFailure）与宿主
// 的状态码映射仍按凭证失效处理，续期原因只作为补充说明附在后面。
func AuthRetryError(errAction, errRefresh error) error {
	if errAction == nil {
		return errRefresh
	}
	if errRefresh == nil {
		return errAction
	}
	return fmt.Errorf("%w；自动续期失败：%v", errAction, errRefresh)
}

// IsTransientFailure 判断错误是否属于「稍后重试可能成功」的传输层故障。
//
// 只认分类结果：按状态码猜（502/503 一律重试）会把「上游明确拒绝」也算进去。
func IsTransientFailure(err error) bool {
	var failure *Failure
	return errors.As(err, &failure) && failure.Kind == FailureKindTransient
}

// IsAuthExpired 判断错误是否属于「凭证已过期/失效」类（401）。
//
// 只认 401：403/404 往往意味着账号没这个权限或上游改版，刷新不会变好，
// 盲目刷新只会白白多打一次上游。
func IsAuthExpired(err error) bool {
	var failure *Failure
	if errors.As(err, &failure) {
		// 只看归一后的状态码：403 的凭证类错误（无权限）刷新不会变好。
		return failure.HTTPStatus() == http.StatusUnauthorized
	}
	var pluginErr *PluginError
	if errors.As(err, &pluginErr) {
		return pluginErr.HTTPStatus == http.StatusUnauthorized
	}
	return false
}

// IsDefinitiveFailure 判断错误是否表示「账号侧已有确定结论」。
//
// 判定用途是「这次没取到额度，还能不能拿上次的读数顶上」：
//   - 瞬时类（限流、超时、5xx、繁忙、WAF 拦截）过一会儿再查就能恢复，
//     展示层可以保留上次读数并明确标注非实时；
//   - 确定类（硬额度耗尽、凭证失效、内容拦截、参数错误、账号异常）不会
//     自己好转，必须如实报错——否则界面会把「额度已经没了」显示成上次的
//     正常读数，用户照着旧数字去用，撞墙才发现。
//
// 非 Failure（网络层错误、上下文取消）一律按瞬时处理：调用方无从判断账号
// 状态，保留上次读数并标注非实时是可接受的。
func IsDefinitiveFailure(err error) bool {
	if err == nil {
		return false
	}
	// 凭证侧的状态码同样是确定结论：401/403 换时间重试不会自己好转，凭证
	// 得重新授权才能用。漏掉这一条会让页面把「凭证已失效」显示成上次的正常
	// 读数（见 #71 第二轮复审 P2-4）。
	var pluginErr *PluginError
	if errors.As(err, &pluginErr) && pluginErr != nil {
		if pluginErr.HTTPStatus == 401 || pluginErr.HTTPStatus == 403 {
			return true
		}
	}
	var failure *Failure
	if !errors.As(err, &failure) {
		return false
	}
	switch failure.Kind {
	case FailureKindHardCredit, FailureKindQuota,
		FailureKindSessionDead, FailureKindCredential,
		FailureKindContentBlocked, FailureKindChannelRejected,
		FailureKindBadParams, FailureKindClient,
		FailureKindAccountFault, FailureKindModelBlocked,
		FailureKindNotFound, FailureKindPromptTooLong, FailureKindImageInvalid:
		return true
	}
	return false
}
