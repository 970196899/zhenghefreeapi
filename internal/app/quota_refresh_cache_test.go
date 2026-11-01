package app

// 额度刷新后回源缓存必须换成新凭证。
//
// 宿主额度路由触发的刷新，会把新 token 直接交给本次重试；但下一次请求仍走
// credentialForAuth → 30 秒缓存。缓存不换，等于「刷新成功、下一个请求继续
// 用旧 token 再撞一次 401」。

import (
	"context"
	"testing"
	"time"

	"freetier2api-plugin/internal/core"
)

func TestStoreCredentialOverwritesCachedToken(t *testing.T) {
	application := &App{credentialCache: make(map[string]credentialCacheEntry)}
	old := &core.Credential{FileID: "auth-1", Token: "old"}
	application.storeCredential("auth-1", old)
	if cached, ok := application.cachedCredential("auth-1"); !ok || cached != old {
		t.Fatalf("首次写入未命中缓存：ok=%v", ok)
	}

	fresh := &core.Credential{FileID: "auth-1", Token: "new"}
	application.storeCredential("auth-1", fresh)
	cached, ok := application.cachedCredential("auth-1")
	if !ok {
		t.Fatal("覆盖写入后缓存丢失")
	}
	if cached.Token != "new" {
		t.Fatalf("缓存仍是 %q，覆盖写入没生效", cached.Token)
	}
}

func TestCachedCredentialExpiresAfterTTL(t *testing.T) {
	application := &App{credentialCache: make(map[string]credentialCacheEntry)}
	application.credentialCache["auth-1"] = credentialCacheEntry{
		credential: &core.Credential{FileID: "auth-1", Token: "stale"},
		fetchedAt:  time.Now().Add(-2 * credentialCacheTTL),
	}
	if _, ok := application.cachedCredential("auth-1"); ok {
		t.Fatal("过期缓存仍被返回，会把失效 token 一直喂给请求")
	}
}

// 刷新成功后必须回写缓存：这是 refreshedQuotaCredential 区别于直接调用
// auth.RefreshCredential 的唯一职责，漏掉就是上面说的「刷新成功、下一请求 401」。
func TestAdoptRefreshedCredentialOverwritesStaleCache(t *testing.T) {
	application := &App{credentialCache: make(map[string]credentialCacheEntry)}
	application.storeCredential("auth-1", &core.Credential{FileID: "auth-1", Token: "old"})

	fresh := &core.Credential{FileID: "auth-1", Token: "new"}
	application.adoptRefreshedCredential("auth-1", fresh)
	if cached, _ := application.cachedCredential("auth-1"); cached.Token != "new" {
		t.Fatalf("缓存仍是 %q，刷新后的 token 没回写", cached.Token)
	}

	// 空凭证 / 空 authID 不得写进缓存：空键会让后续所有查询串味。
	application.adoptRefreshedCredential("", &core.Credential{Token: "orphan"})
	application.adoptRefreshedCredential("auth-2", nil)
	if _, ok := application.cachedCredential(""); ok {
		t.Fatal("空 authID 被写进缓存")
	}
	if _, ok := application.cachedCredential("auth-2"); ok {
		t.Fatal("nil 凭证被写进缓存")
	}
}

// vendor 为 nil 时不刷新，也不该污染缓存。
func TestRefreshedQuotaCredentialWithoutVendorKeepsCache(t *testing.T) {
	application := &App{credentialCache: make(map[string]credentialCacheEntry)}
	application.storeCredential("auth-1", &core.Credential{FileID: "auth-1", Token: "old"})

	if credential, errRefresh := application.refreshedQuotaCredential(context.Background(), "cb", "auth-1", nil); errRefresh != nil || credential != nil {
		t.Fatal("vendor 为 nil 时应返回 nil")
	}
	if cached, _ := application.cachedCredential("auth-1"); cached.Token != "old" {
		t.Fatal("vendor 为 nil 时缓存被改动")
	}
}
