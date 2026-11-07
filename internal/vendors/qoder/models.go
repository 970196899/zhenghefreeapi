package qoder

// 本文件实现 Qoder 的模型清单。
//
// 清单只有一条来源：上游 model/list 接口（需要 cosy 会话）。**不维护内置
// 兜底清单**——写死的模型名会随上游变化而过时，反而让客户端看到一份
// 并不存在的目录。拉不到就返回空清单，由控制台提示「刷新模型」。

import (
	"strings"
	"sync"

	"freetier2api-plugin/internal/logger"
)

// modelIndex 是某区域实例的「对外模型 ID / 上游 key → 上游 key」索引。
//
// 为什么是实例状态而不是包级表：Qoder 国内版与国际版是两个 adapter 实例，
// 同一个上游 key 在两个区域可能对应不同模型（如 mmodel 在国内是
// MiniMax-M2.7、国际是 MiniMax-M3）。放进实例里，两边各自维护，
// 与仓库「实例隔离」的约定一致。
//
// 为什么是动态建立而不是写死静态表：slug → key 的对应关系只存在于上游
// 清单的 {key, display_name} 配对里。写死一张表意味着上游每换一个模型就要
// 改代码，而且容易把两个不同模型误绑到同一个名字；从清单推导则天然跟随上游。
type modelIndex struct {
	mu            sync.RWMutex
	byName        map[string]string
	reasoningKeys map[string]bool
}

// replace 用一批上游模型条目重建索引，返回「上游 key → 对外 ID」。
//
// 重复 ID（上游出现同名 display_name）时只有第一条保留，其余不出现在返回值里，
// 由调用方跳过——宿主按 ID 匹配模型，注册两个相同 ID 只会让其中一个永远选不到。
func (i *modelIndex) replace(models []Model) map[string]string {
	byName := make(map[string]string, len(models)*2)
	slugByKey := make(map[string]string, len(models))
	reasoningKeys := make(map[string]bool, len(models))
	for _, model := range models {
		key := strings.TrimSpace(model.Key)
		if key == "" {
			continue
		}
		id := canonicalModelID(model.DisplayName, key)
		if id == "" {
			continue
		}
		if _, exists := byName[id]; exists {
			logger.Info("qoder: duplicate model id %q (key %s), skipping", id, key)
			continue
		}
		slugByKey[key] = id
		byName[id] = key
		if model.IsReasoning {
			reasoningKeys[strings.ToLower(id)] = true
			reasoningKeys[strings.ToLower(key)] = true
		}
		// 老客户端仍可能直接发上游 key（dmodel / gmodel …）：一并接受。
		// 对外 ID 优先——万一某个 slug 恰好等于另一个模型的上游 key，
		// 以清单里声明的 slug 为准。
		lowerKey := strings.ToLower(key)
		if _, exists := byName[lowerKey]; !exists {
			byName[lowerKey] = key
		}
	}
	i.mu.Lock()
	i.byName = byName
	i.reasoningKeys = reasoningKeys
	i.mu.Unlock()
	return slugByKey
}

// IsReasoningModel 判断对外模型名（slug 或上游 key）是否指向推理模型。
// 索引未建立或名称未命中时返回 false；用于「推理模型默认开启深度思考」判定。
func (i *modelIndex) IsReasoningModel(name string) bool {
	if i == nil {
		return false
	}
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	if key, ok := i.byName[trimmed]; ok {
		trimmed = strings.ToLower(key)
	}
	return i.reasoningKeys[trimmed]
}

// UpstreamKey 把对外模型名解析成上游 model_config.key。大小写不敏感。
func (i *modelIndex) UpstreamKey(name string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" {
		return "", false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	key, ok := i.byName[trimmed]
	return key, ok
}

// canonicalModelID 把上游 display_name 规范成对外模型 ID：
// 小写，空白折叠成单个 "-"（"DeepSeek-V4-Pro" -> "deepseek-v4-pro"）。
//
// display_name 缺失时退回上游 key 的小写形式，保证总能拿到一个可用 ID。
func canonicalModelID(displayName, key string) string {
	slug := strings.ToLower(strings.TrimSpace(displayName))
	slug = strings.Join(strings.Fields(slug), "-")
	if slug == "" {
		slug = strings.ToLower(strings.TrimSpace(key))
	}
	return slug
}
