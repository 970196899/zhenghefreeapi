package qoder

import (
	"io"
	"reflect"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadQoderResponseBodyLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Repeat("x", int(shortResponseMaxBytes)+1))
	}))
	defer server.Close()

	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if _, err = readQoderResponseBody(resp.Body); err == nil {
		t.Fatal("expected oversized response to be rejected")
	} else if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unexpected oversized response error: %v", err)
	}
}

func TestReadQoderResponseBodyAllowsNormalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()

	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := readQoderResponseBody(resp.Body)
	if err != nil {
		t.Fatalf("normal response rejected: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q", body)
	}
}

func TestMergeToolCallDeltas(t *testing.T) {
	delta1 := []interface{}{
		map[string]interface{}{
			"index": 0,
			"id":    "call_bash_1",
			"type":  "function",
			"function": map[string]interface{}{
				"name":      "Bash",
				"arguments": "{\"command\": \"",
			},
		},
	}
	delta2 := []interface{}{
		map[string]interface{}{
			"index": 0,
			"function": map[string]interface{}{
				"arguments": "ls -la\"}",
			},
		},
	}
	delta3Bad := []interface{}{
		map[string]interface{}{
			"index": 1,
			"id":    "call_unnamed",
			"type":  "function",
			"function": map[string]interface{}{
				"name":      "",
				"arguments": "{}",
			},
		},
	}

	var accumulated []interface{}
	accumulated = mergeToolCallDeltas(accumulated, delta1)
	accumulated = mergeToolCallDeltas(accumulated, delta2)
	accumulated = mergeToolCallDeltas(accumulated, delta3Bad)

	valid := filterValidToolCalls(accumulated)
	if len(valid) != 1 {
		t.Fatalf("expected 1 valid tool call after filtering unnamed calls, got %d", len(valid))
	}

	call := valid[0].(map[string]interface{})
	if call["id"] != "call_bash_1" {
		t.Errorf("expected id 'call_bash_1', got %v", call["id"])
	}
	fn := call["function"].(map[string]interface{})
	if fn["name"] != "Bash" {
		t.Errorf("expected name 'Bash', got %v", fn["name"])
	}
	if fn["arguments"] != `{"command": "ls -la"}` {
		t.Errorf("expected merged arguments '{\"command\": \"ls -la\"}', got %v", fn["arguments"])
	}
}

// ==================== 专有协议测试 ====================

func TestMapModel(t *testing.T) {
	// MapModel 只处理「索引未命中」的兜底：本插件自己注册的模型由
	// Bridge.resolveModel 先走 modelIndex（见 TestBridgeResolveModel）。
	cases := []struct {
		agent    string
		model    string
		expected string
	}{
		{"codex", "gfmodel", "gfmodel"},
		{"codex", "gmodel", "gmodel"},
		{"codex", "kmodel_latest", "kmodel_latest"},
		{"codex", "qmodel_38max", "qmodel_38max"},
		{"claude", "claude-sonnet-4-6", "gmodel"}, // sonnet 模糊匹配兜底
		{"codex", "Performance", "performance"},   // 大小写归一
	}

	for _, c := range cases {
		got := MapModel(c.agent, c.model)
		if got != c.expected {
			t.Errorf("MapModel(%q, %q) = %q; want %q", c.agent, c.model, got, c.expected)
		}
	}
}

func TestBridgeResolveModel(t *testing.T) {
	var index modelIndex
	index.replace(testModels())
	bridge := &Bridge{models: &index}

	cases := []struct {
		agent    string
		model    string
		expected string
	}{
		// 对外 slug → 上游 key
		{"codex", "deepseek-v4-pro", "dmodel"},
		{"codex", "qwen3.8-max", "qmodel_38max"},
		{"codex", "glm-5.3", "gmodel"},
		// 大小写不敏感
		{"codex", "DeepSeek-V4-Pro", "dmodel"},
		// 旧上游 key 仍可直传（向后兼容）
		{"codex", "dmodel", "dmodel"},
		{"codex", "qmodel_38max", "qmodel_38max"},
		// 索引未命中 → 内置映射兜底
		{"claude", "claude-sonnet-4-6", "gmodel"},
	}
	for _, c := range cases {
		if got := bridge.resolveModel(c.agent, c.model); got != c.expected {
			t.Errorf("resolveModel(%q, %q) = %q; want %q", c.agent, c.model, got, c.expected)
		}
	}
}

func TestBridgeResolveModelWithoutIndex(t *testing.T) {
	// 没有索引时（测试/独立构造）退回 MapModel，行为与变更前一致。
	bridge := &Bridge{}
	if got := bridge.resolveModel("claude", "claude-sonnet-4-6"); got != "gmodel" {
		t.Errorf("resolveModel without index = %q; want gmodel", got)
	}
}

// ---- 模型目录全量合并、1M 上下文与推理档位（Spec 2026-11-07）----

// mkQoderModel 构造一条上游模型条目；context_config 采用对象包数组形态，
// 同时含 195K 默认档与指定旗舰档，用来验证「只选默认档」的旧实现被淘汰。
func mkQoderModel(key, name string, flagshipTokens int, reasoning bool) map[string]interface{} {
	return map[string]interface{}{
		"key":              key,
		"display_name":     name,
		"enable":           true,
		"is_reasoning":     reasoning,
		"max_input_tokens": 200000,
		"context_config": map[string]interface{}{
			"tiers": []interface{}{
				map[string]interface{}{"is_default": true, "token_count": 195000},
				map[string]interface{}{"is_default": false, "token_count": flagshipTokens},
			},
		},
	}
}

func TestParseModelsMergesAllCategoriesAndPrefersRicher(t *testing.T) {
	resp := map[string]interface{}{
		"chat":      []interface{}{mkQoderModel("gmodel", "GLM-5.3", 200000, false)},
		"assistant": []interface{}{mkQoderModel("dmodel", "DeepSeek-V4-Pro", 195000, false)},
		"developer": []interface{}{
			mkQoderModel("qmodel_x", "Qwen3.9-Coder", 1000000, false),
			// 与 assistant 重复 Key：上下文更大 → 择优替换
			mkQoderModel("dmodel", "DeepSeek-V4-Pro", 1000000, false),
		},
		"future_cat": []interface{}{mkQoderModel("nmodel", "NewModel", 128000, false)},
	}
	models := parseModels(resp)
	if len(models) != 4 {
		t.Fatalf("模型数 = %d, want 4（全量合并去重）", len(models))
	}
	wantOrder := []string{"dmodel", "qmodel_x", "gmodel", "nmodel"}
	for i, want := range wantOrder {
		if models[i].Key != want {
			t.Fatalf("models[%d].Key = %q, want %q（已知分类固定顺序在前，其余键升序）", i, models[i].Key, want)
		}
	}
	if models[0].ContextWindow != 1000000 {
		t.Fatalf("重复 Key 择优失败: dmodel.ContextWindow = %d, want 1000000", models[0].ContextWindow)
	}
}

func TestExtractModelsPrefers1MContext(t *testing.T) {
	cases := []struct {
		name string
		item map[string]interface{}
		want int
	}{
		{"对象包数组含1M档", mkQoderModel("a", "A", 1000000, false), 1000000},
		{"裸数组含1M档", map[string]interface{}{
			"key": "b", "display_name": "B", "enable": true,
			"context_config": []interface{}{
				map[string]interface{}{"is_default": true, "token_count": 195000},
				map[string]interface{}{"is_default": false, "token_count": 1000000},
			},
		}, 1000000},
		{"无context_config回退max_input_tokens", map[string]interface{}{
			"key": "c", "display_name": "C", "enable": true, "max_input_tokens": float64(200000),
		}, 200000},
		{"大值不被1M压低", map[string]interface{}{
			"key": "d", "display_name": "D", "enable": true, "max_input_tokens": float64(1500000),
		}, 1500000},
		{"全缺底线兜底1M", map[string]interface{}{"key": "e", "display_name": "E", "enable": true}, 1000000},
	}
	for _, c := range cases {
		got := extractModels([]interface{}{c.item})
		if len(got) != 1 {
			t.Fatalf("%s: extractModels 返回 %d 条, want 1", c.name, len(got))
		}
		if got[0].ContextWindow != c.want {
			t.Errorf("%s: ContextWindow = %d, want %d", c.name, got[0].ContextWindow, c.want)
		}
	}
}

func TestReasoningModelEffortsMetadata(t *testing.T) {
	cases := []struct {
		name           string
		item           map[string]interface{}
		wantEfforts    []string
		wantDefault    string
		wantMaxOutput  int
	}{
		{"物理字段推理", mkQoderModel("r1", "R1", 1000000, true), []string{"low", "medium", "high", "max"}, "high", 32768},
		{"名称特征串兜底", map[string]interface{}{
			"key": "r2", "display_name": "GLM-5.3-Reasoning", "enable": true,
		}, []string{"low", "medium", "high", "max"}, "high", 32768},
		{"普通模型不宣告", mkQoderModel("n1", "N1", 200000, false), nil, "", 16384},
	}
	for _, c := range cases {
		got := extractModels([]interface{}{c.item})[0]
		if !reflect.DeepEqual(got.Efforts, c.wantEfforts) {
			t.Errorf("%s: Efforts = %v, want %v", c.name, got.Efforts, c.wantEfforts)
		}
		if got.DefaultEffort != c.wantDefault {
			t.Errorf("%s: DefaultEffort = %q, want %q", c.name, got.DefaultEffort, c.wantDefault)
		}
		if got.MaxOutputTokens != c.wantMaxOutput {
			t.Errorf("%s: MaxOutputTokens = %d, want %d", c.name, got.MaxOutputTokens, c.wantMaxOutput)
		}
	}
}

func TestFloatPtrStringTolerance(t *testing.T) {
	cases := []struct {
		name string
		raw  map[string]interface{}
		want *float64
	}{
		{"字符串1.0", map[string]interface{}{"price_factor": "1.0"}, float64Ptr(1.0)},
		{"字符串0.5", map[string]interface{}{"price_factor": "0.5"}, float64Ptr(0.5)},
		{"浮点0.42", map[string]interface{}{"price_factor": 0.42}, float64Ptr(0.42)},
		{"非数字字符串", map[string]interface{}{"price_factor": "abc"}, nil},
		{"缺字段", map[string]interface{}{}, nil},
	}
	for _, c := range cases {
		got := FloatPtr(c.raw, "price_factor")
		if (got == nil) != (c.want == nil) {
			t.Errorf("%s: FloatPtr = %v, want %v", c.name, got, c.want)
			continue
		}
		if got != nil && c.want != nil && *got != *c.want {
			t.Errorf("%s: FloatPtr = %v, want %v", c.name, *got, *c.want)
		}
	}
}
