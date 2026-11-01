package trae

// 协议层单测：用 httptest + hostbridge 直连桩固化 TraeCode 协议契约。
// fixture 均来自上游真实响应（2026-10 抓取），不访问外网。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
)

// stubHost 装配直连宿主桥（http.do 与 SSE 流式两条路径）。
//
// 流式路径按宿主契约交付：先投数据（done=false），再空读置 done=true。
func stubHost(t *testing.T) {
	t.Helper()
	var (
		mu     sync.Mutex
		bodies = map[string][]byte{}
		nextID int
	)
	hostbridge.Configure(func(callbackID, method string, payload any) (json.RawMessage, error) {
		raw, errMarshal := json.Marshal(payload)
		if errMarshal != nil {
			return nil, errMarshal
		}
		var req struct {
			Method   string              `json:"method"`
			URL      string              `json:"url"`
			Headers  map[string][]string `json:"headers"`
			Body     []byte              `json:"body"`
			StreamID string              `json:"stream_id"`
		}
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return nil, errUnmarshal
		}
		switch method {
		case pluginabi.MethodHostHTTPDo:
			status, header, body, errDo := stubUpstream(req.Method, req.URL, req.Headers, req.Body)
			if errDo != nil {
				return nil, errDo
			}
			return json.Marshal(map[string]any{"StatusCode": status, "Headers": header, "Body": body})
		case pluginabi.MethodHostHTTPDoStream:
			status, header, body, errDo := stubUpstream(req.Method, req.URL, req.Headers, req.Body)
			if errDo != nil {
				return nil, errDo
			}
			mu.Lock()
			nextID++
			streamID := fmt.Sprintf("stub-%d", nextID)
			bodies[streamID] = body
			mu.Unlock()
			return json.Marshal(map[string]any{"status_code": status, "headers": header, "stream_id": streamID})
		case pluginabi.MethodHostHTTPStreamRead:
			mu.Lock()
			body, okBody := bodies[req.StreamID]
			if okBody {
				delete(bodies, req.StreamID)
			}
			mu.Unlock()
			if okBody {
				return json.Marshal(map[string]any{"payload": body, "done": false})
			}
			return json.Marshal(map[string]any{"done": true})
		case pluginabi.MethodHostHTTPStreamClose:
			return json.Marshal(map[string]any{})
		default:
			return nil, fmt.Errorf("stub host: unsupported method %s", method)
		}
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
}

func stubUpstream(method, url string, headers map[string][]string, body []byte) (int, http.Header, []byte, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = strings.NewReader(string(body))
	}
	httpReq, errNew := http.NewRequest(method, url, reader)
	if errNew != nil {
		return 0, nil, nil, errNew
	}
	for key, values := range headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}
	resp, errDo := (&http.Client{}).Do(httpReq)
	if errDo != nil {
		return 0, nil, nil, errDo
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return 0, nil, nil, errRead
	}
	return resp.StatusCode, resp.Header, respBody, nil
}

// testConfig 返回指向桩服务器的国内版 profile。
func testConfig(t *testing.T, serverURL string) Config {
	t.Helper()
	cfg := ConfigFor(RegionCN)
	cfg.ChatHost = serverURL
	cfg.AuthHost = serverURL
	cfg.RefreshHost = serverURL
	cfg.CheckinHost = serverURL
	cfg.QuotaHost = serverURL
	return cfg
}

func testCredential() *Credential {
	return &Credential{
		Vendor:       VendorIDCN,
		Region:       RegionCN,
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		UID:          "2487573687317868",
	}
}

// ---- fixture：上游真实响应 ----

const chatSSEFixture = `id: 1
event: metadata
data: {"model":"","session_id":"s-1"}

id: 2
event: timing_cost
data: {"name":"llm_raw_chat_v2"}

id: 3
event: output
data: {"response":"","reasoning_content":"思考","tool_calls":null}

id: 4
event: output
data: {"response":"你好","reasoning_content":null,"tool_calls":null}

id: 5
event: token_usage
data: {"prompt_tokens":16,"completion_tokens":479,"total_tokens":495,"reasoning_tokens":460}

id: 6
event: done
data: {"finish_reason":"stop"}

`

// chatToolCallSSEFixture：上游触发工具调用的真实事件形态（2026-11-01 抓包样例 + 无 id 增量块）。
const chatToolCallSSEFixture = `id: 1
event: output
data: {"response":"","reasoning_content":"","tool_calls":[{"index":0,"id":"call_x1","type":"function","function_call":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]}

id: 2
event: output
data: {"tool_calls":[{"index":0,"function_call":{"arguments":" -la"}}]}

id: 3
event: done
data: {"finish_reason":"tool_calls"}

`

// chatToolAggSSEFixture：非流式聚合用——index 1 先到、index 0 拆两段 arguments。
const chatToolAggSSEFixture = `id: 1
event: output
data: {"response":"","tool_calls":[{"index":1,"id":"call_b","type":"function","function_call":{"name":"Read","arguments":"{\"path\":\"a.go\"}"}}]}

id: 2
event: output
data: {"tool_calls":[{"index":0,"id":"call_a","type":"function","function_call":{"name":"Bash","arguments":"{\"command\":"}}]}

id: 3
event: output
data: {"tool_calls":[{"index":0,"function_call":{"arguments":"\"ls -la\"}"}}]}

id: 4
event: done
data: {"finish_reason":"tool_calls"}

`

const catalogFixture = `{
  "allow_tenant_user_add_model": true,
  "config_info_list": [
    {
      "config_name": "glm-5.2",
      "config_switch": true,
      "usage": "chat_completion",
      "context_window_tokens": {"dev": 200000},
      "display_config": {"display_name": "GLM-5.2", "model_capability": "reasoning_model"},
      "extra_config": "{\"native_function_call\":true}",
      "model_detail_list": [{"model_name": "glm-5.2__dev", "max_tokens": 32000}]
    },
    {
      "config_name": "DeepSeek-V4-Pro",
      "config_switch": true,
      "usage": "chat_completion",
      "context_window_tokens": {"dev": 200000},
      "display_config": {"display_name": "DeepSeek-V4-Pro", "model_capability": "reasoning_model"},
      "extra_config": "{}",
      "model_detail_list": [{"model_name": "DeepSeek-V4-Pro__dev", "max_tokens": 32000}]
    },
    {
      "config_name": "deepseek-v4.1-flash",
      "config_switch": true,
      "usage": "chat_completion",
      "context_window_tokens": {"dev": 200000},
      "display_config": {"display_name": "DeepSeek-V4.1-Flash", "model_capability": "reasoning_model"},
      "extra_config": "{}",
      "model_detail_list": [{"model_name": "deepseek-v4.1-flash__dev", "max_tokens": 32000}]
    },
    {
      "config_name": "custom_model_gpt-5",
      "config_switch": true,
      "usage": "custom_model",
      "context_window_tokens": {"dev": 200000},
      "display_config": {"display_name": "GPT-5", "model_capability": "chat_model"},
      "model_detail_list": [{"model_name": "custom_model_gpt-5__max", "max_tokens": 32000}]
    },
    {
      "config_name": "glm-5-off",
      "config_switch": false,
      "usage": "chat_completion",
      "model_detail_list": [{"model_name": "glm-5-off__dev", "max_tokens": 32000}]
    }
  ]
}`

const quotaFixture = `{
  "is_credits_billing": true,
  "usage_summary": {"consumed_amount": 0.49, "total_amount": 4600},
  "user_entitlement_pack_list": [
    {
      "entitlement_base_info": {"product_type": 2, "quota": {"credits_limit": 4000}},
      "usage": {"credits_amount": ""}
    },
    {
      "entitlement_base_info": {"product_type": 0, "quota": {}},
      "usage": {"credits_amount": ""}
    },
    {
      "entitlement_base_info": {"product_type": 2, "quota": {"credits_limit": 500}},
      "usage": {"credits_amount": 0.4944}
    },
    {
      "entitlement_base_info": {"product_type": 2, "quota": {"credits_limit": 100}},
      "usage": {}
    }
  ]
}`

// ---- 请求体 / 请求头 ----

func TestPrepareBodyBuildsTraeCodeEnvelope(t *testing.T) {
	cfg := ConfigFor(RegionCN)
	resolved := ResolvedModel{ConfigName: "glm-5.2", WireName: "glm-5.2__dev"}
	src := []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"stream":false,"temperature":0.5}`)

	body, model, errPrep := PrepareBody(src, cfg, resolved)
	if errPrep != nil {
		t.Fatalf("PrepareBody: %v", errPrep)
	}
	if model != "glm-5.2" {
		t.Fatalf("model = %q, want glm-5.2", model)
	}

	var got map[string]any
	if errJSON := json.Unmarshal(body, &got); errJSON != nil {
		t.Fatalf("decode body: %v", errJSON)
	}
	if got["config_name"] != "glm-5.2" {
		t.Errorf("config_name = %v", got["config_name"])
	}
	if got["model_name"] != "glm-5.2__dev" {
		t.Errorf("model_name = %v, want glm-5.2__dev", got["model_name"])
	}
	if got["raw_chat_function"] != "chat_v3" {
		t.Errorf("raw_chat_function = %v", got["raw_chat_function"])
	}
	if got["config_source"] != float64(1) {
		t.Errorf("config_source = %v", got["config_source"])
	}
	if got["stream"] != true {
		t.Errorf("stream = %v, want true（上游只讲 SSE）", got["stream"])
	}
	if got["conversation_id"] == "" || got["conversation_id"] != got["session_id"] {
		t.Errorf("conversation_id/session_id 不匹配: %v / %v", got["conversation_id"], got["session_id"])
	}
	if _, ok := got["model"]; ok {
		t.Error("顶层 model 字段应被删除（避免与 model_name 混淆）")
	}
	// 透传字段保留。
	if got["temperature"] != 0.5 {
		t.Errorf("temperature 丢失: %v", got["temperature"])
	}
	// content 包成块数组。
	msgs, _ := got["messages"].([]any)
	first, _ := msgs[0].(map[string]any)
	blocks, okBlocks := first["content"].([]any)
	if !okBlocks || len(blocks) != 1 {
		t.Fatalf("content 未转成块数组: %v", first["content"])
	}
	block, _ := blocks[0].(map[string]any)
	if block["type"] != "text" || block["text"] != "hi" {
		t.Errorf("content 块不对: %v", block)
	}
}

// TestPrepareBodyNormalizesOpenAITools 锁定上行 tools 契约：
// OpenAI 嵌套格式 [{type:"function", function:{...}}] 必须保持嵌套结构，
// 且 function.parameters 必须序列化为 JSON 字符串（Trae Go 后端按 string 反序列化，
// 传对象会被判无工具或直接 400，见 2026-11-01 bidirectional spec）。
func TestPrepareBodyNormalizesOpenAITools(t *testing.T) {
	cfg := ConfigFor(RegionCN)
	resolved := ResolvedModel{ConfigName: "glm-5.2", WireName: "glm-5.2__dev"}
	src := []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"tools":[
		{"type":"function","function":{"name":"get_weather","description":"查天气","parameters":{"type":"object","properties":{}}}}
	]}`)

	body, _, errPrep := PrepareBody(src, cfg, resolved)
	if errPrep != nil {
		t.Fatalf("PrepareBody: %v", errPrep)
	}
	var got map[string]any
	if errJSON := json.Unmarshal(body, &got); errJSON != nil {
		t.Fatalf("decode body: %v", errJSON)
	}
	tools, okTools := got["tools"].([]any)
	if !okTools || len(tools) != 1 {
		t.Fatalf("tools 应为长度 1 的数组: %v", got["tools"])
	}
	tool, _ := tools[0].(map[string]any)
	if tool["type"] != "function" {
		t.Errorf("外层 type 应为 function: %v", tool)
	}
	fn, okFn := tool["function"].(map[string]any)
	if !okFn {
		t.Fatalf("function 嵌套缺失: %v", tool)
	}
	if fn["name"] != "get_weather" || fn["description"] != "查天气" {
		t.Errorf("function 字段未正确挂载: %v", fn)
	}
	params, okParams := fn["parameters"].(string)
	if !okParams {
		t.Fatalf("parameters 应为字符串, got %T", fn["parameters"])
	}
	var back map[string]any
	if errBack := json.Unmarshal([]byte(params), &back); errBack != nil {
		t.Fatalf("parameters 不是合法 JSON: %v (%s)", errBack, params)
	}
	if back["type"] != "object" {
		t.Errorf("parameters 回读 type = %v", back["type"])
	}
	// content 块包装不受归一化影响。
	msgs, _ := got["messages"].([]any)
	first, _ := msgs[0].(map[string]any)
	if _, okBlocks := first["content"].([]any); !okBlocks {
		t.Errorf("content 块包装被破坏: %v", first["content"])
	}
}

// 扁平输入必须重包装为嵌套+字符串化（幂等向上兼容）。
func TestPrepareBodyConvertsFlatToolsToNested(t *testing.T) {
	cfg := ConfigFor(RegionCN)
	resolved := ResolvedModel{ConfigName: "glm-5.2", WireName: "glm-5.2__dev"}
	src := []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"tools":[
		{"name":"get_weather","description":"查天气","parameters":{"type":"object"}}
	]}`)

	body, _, errPrep := PrepareBody(src, cfg, resolved)
	if errPrep != nil {
		t.Fatalf("PrepareBody: %v", errPrep)
	}
	var got map[string]any
	if errJSON := json.Unmarshal(body, &got); errJSON != nil {
		t.Fatalf("decode body: %v", errJSON)
	}
	tools, _ := got["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools 长度 = %d, want 1", len(tools))
	}
	tool, _ := tools[0].(map[string]any)
	if tool["type"] != "function" {
		t.Errorf("扁平输入应转嵌套: %v", tool)
	}
	fn, _ := tool["function"].(map[string]any)
	if fn["name"] != "get_weather" || fn["description"] != "查天气" {
		t.Errorf("扁平字段未正确提升: %v", fn)
	}
	if p, ok := fn["parameters"].(string); !ok || p != `{"type":"object"}` {
		t.Errorf("扁平对象参数应序列化为字符串: %v", fn["parameters"])
	}
}

// 未传 tools / tools 为空数组时必须零改动。
func TestPrepareBodyLeavesMissingOrEmptyTools(t *testing.T) {
	cfg := ConfigFor(RegionCN)
	resolved := ResolvedModel{ConfigName: "glm-5.2", WireName: "glm-5.2__dev"}

	for name, src := range map[string][]byte{
		"无tools":   []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`),
		"空tools":   []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"tools":[]}`),
		"非数组tools": []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"tools":null}`),
	} {
		body, _, errPrep := PrepareBody(src, cfg, resolved)
		if errPrep != nil {
			t.Fatalf("%s: PrepareBody: %v", name, errPrep)
		}
		var got map[string]any
		if errJSON := json.Unmarshal(body, &got); errJSON != nil {
			t.Fatalf("%s: decode body: %v", name, errJSON)
		}
		if v, present := got["tools"]; present && v != nil {
			if arr, ok := v.([]any); !ok || len(arr) != 0 {
				t.Errorf("%s: tools 不应被改写: %v", name, v)
			}
		}
	}
}

// TestPrepareBodySerializesToolParameters 锁定核心契约：
// parameters 恒为合法 JSON 字符串——对象自动序列化、字符串原样透传、缺失补默认。
func TestPrepareBodySerializesToolParameters(t *testing.T) {
	cfg := ConfigFor(RegionCN)
	resolved := ResolvedModel{ConfigName: "glm-5.2", WireName: "glm-5.2__dev"}

	cases := map[string]struct {
		tool  string
		check func(t *testing.T, fn map[string]any)
	}{
		"对象参数序列化": {
			tool:  `{"type":"function","function":{"name":"get_weather","description":"查天气","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}`,
			check: func(t *testing.T, fn map[string]any) {
				p, ok := fn["parameters"].(string)
				if !ok {
					t.Fatalf("parameters 应为字符串, got %T", fn["parameters"])
				}
				var back map[string]any
				if err := json.Unmarshal([]byte(p), &back); err != nil {
					t.Fatalf("参数字符串非法: %v", err)
				}
				props, _ := back["properties"].(map[string]any)
				city, _ := props["city"].(map[string]any)
				if back["type"] != "object" || city["type"] != "string" {
					t.Errorf("序列化丢失结构: %s", p)
				}
			},
		},
		"字符串参数透传": {
			tool:  `{"type":"function","function":{"name":"get_weather","description":"查天气","parameters":"{\"type\":\"object\"}"}}`,
			check: func(t *testing.T, fn map[string]any) {
				if p, _ := fn["parameters"].(string); p != `{"type":"object"}` {
					t.Errorf("字符串参数被二次转义: %q", fn["parameters"])
				}
			},
		},
		"缺失参数补默认": {
			tool:  `{"type":"function","function":{"name":"no_params","description":"d"}}`,
			check: func(t *testing.T, fn map[string]any) {
				if p, _ := fn["parameters"].(string); p != `{"type":"object","properties":{}}` {
					t.Errorf("缺参应补默认字面量: %q", fn["parameters"])
				}
			},
		},
		"无名工具跳过": {
			tool:  `{"type":"function","function":{"description":"没有名字"}}`,
			check: func(t *testing.T, fn map[string]any) {
				t.Fatalf("无名工具不应产出: %v", fn)
			},
		},
	}

	for name, tc := range cases {
		src := []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"tools":[` + tc.tool + `]}`)
		body, _, errPrep := PrepareBody(src, cfg, resolved)
		if errPrep != nil {
			t.Fatalf("%s: PrepareBody: %v", name, errPrep)
		}
		var got map[string]any
		if errJSON := json.Unmarshal(body, &got); errJSON != nil {
			t.Fatalf("%s: decode body: %v", name, errJSON)
		}
		toolList, _ := got["tools"].([]any)
		if name == "无名工具跳过" {
			if len(toolList) != 0 {
				t.Errorf("%s: tools 应为空, got %v", name, got["tools"])
			}
			continue
		}
		if len(toolList) != 1 {
			t.Fatalf("%s: tools 长度 = %d, want 1", name, len(toolList))
		}
		tool, _ := toolList[0].(map[string]any)
		fn, _ := tool["function"].(map[string]any)
		tc.check(t, fn)
	}
}

func TestApplyTraeHeadersSetsIDEIdentity(t *testing.T) {
	cfg := ConfigFor(RegionCN)
	cred := testCredential()
	req, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
	ApplyTraeHeaders(req, cred, cfg, true)

	want := map[string]string{
		"Authorization":        "Cloud-IDE-JWT test-access-token",
		"X-Cloudide-Token":     "test-access-token",
		"X-Ide-Token":          "test-access-token",
		"X-App-Id":             AppID,
		"X-App-Version":        "default",
		"X-Ide-Version":        IDEVersionCN,
		"X-Ide-Version-Code":   IDEVersionCodeCN,
		"X-Ide-Version-Type":   "stable",
		"X-App-Function":       "chat_v3",
		"X-Ide-Function":       "chat_v3",
		"Accept":               "text/event-stream",
		"Request-Traffic-Type": "prod",
	}
	for key, value := range want {
		if got := req.Header.Get(key); got != value {
			t.Errorf("header %s = %q, want %q", key, got, value)
		}
	}
	if req.Header.Get("X-Request-Id") == "" {
		t.Error("X-Request-Id 未设置")
	}
}

func TestProfileCheckinSupport(t *testing.T) {
	if !ConfigFor(RegionCN).supportsCheckin() {
		t.Error("国内版应支持签到")
	}
	if ConfigFor(RegionGlobal).supportsCheckin() {
		t.Error("国际版不应支持签到")
	}
	if cfg := ConfigFor(RegionCN); cfg.Function != "chat_v3" {
		t.Fatalf("国内版 function = %q, want chat_v3", cfg.Function)
	}
}

// ---- 对话（桩服务器） ----

func TestChatAggregatesSSEIntoOpenAIResponse(t *testing.T) {
	stubHost(t)
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case EpModels:
			_, _ = w.Write([]byte(catalogFixture))
		case EpChat:
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &gotBody)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(chatSSEFixture))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	body, errChat := Chat(context.Background(), "", ChatRequest{
		Credential: testCredential(),
		Profile:    cfg,
		Body:       []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`),
	})
	if errChat != nil {
		t.Fatalf("Chat: %v", errChat)
	}

	// 请求体走 TraeCode 协议。
	if gotBody["model_name"] != "glm-5.2__dev" {
		t.Errorf("上游收到的 model_name = %v", gotBody["model_name"])
	}
	if gotBody["raw_chat_function"] != "chat_v3" {
		t.Errorf("上游收到的 raw_chat_function = %v", gotBody["raw_chat_function"])
	}

	var got map[string]any
	if errJSON := json.Unmarshal(body, &got); errJSON != nil {
		t.Fatalf("decode response: %v", errJSON)
	}
	if got["object"] != "chat.completion" {
		t.Errorf("object = %v", got["object"])
	}
	choices, _ := got["choices"].([]any)
	choice, _ := choices[0].(map[string]any)
	message, _ := choice["message"].(map[string]any)
	if message["content"] != "你好" {
		t.Errorf("content = %v, want 你好", message["content"])
	}
	if message["reasoning_content"] != "思考" {
		t.Errorf("reasoning_content = %v, want 思考", message["reasoning_content"])
	}
	if choice["finish_reason"] != "stop" {
		t.Errorf("finish_reason = %v", choice["finish_reason"])
	}
	usage, _ := got["usage"].(map[string]any)
	if usage["total_tokens"] != float64(495) {
		t.Errorf("usage.total_tokens = %v", usage["usage"])
	}
}

func TestChatStreamEmitsOpenAIChunks(t *testing.T) {
	stubHost(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case EpModels:
			_, _ = w.Write([]byte(catalogFixture))
		case EpChat:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(chatSSEFixture))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	var chunks []string
	errStream := ChatStream(context.Background(), "", ChatRequest{
		Credential: testCredential(),
		Profile:    cfg,
		Body:       []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`),
	}, func(chunk []byte) error {
		chunks = append(chunks, string(chunk))
		return nil
	})
	if errStream != nil {
		t.Fatalf("ChatStream: %v", errStream)
	}
	if len(chunks) == 0 {
		t.Fatal("没有产出 chunk")
	}
	joined := strings.Join(chunks, "")
	if !strings.Contains(joined, `"chat.completion.chunk"`) {
		t.Error("chunk 不是 OpenAI 流式格式")
	}
	if !strings.Contains(joined, "思考") || !strings.Contains(joined, "你好") {
		t.Error("chunk 缺少思维链或正文增量")
	}
	if !strings.Contains(joined, `"finish_reason":"stop"`) {
		t.Error("缺少终止 chunk")
	}
}

// TestChatStreamEmitsToolCalls 锁定流式下行：function_call 映射为 OpenAI delta function 形态，
// 无 id 的增量块原样透传，done 事件的 finish_reason=tool_calls 正确闭环。
func TestChatStreamEmitsToolCalls(t *testing.T) {
	stubHost(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case EpModels:
			_, _ = w.Write([]byte(catalogFixture))
		case EpChat:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(chatToolCallSSEFixture))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	var chunks []map[string]any
	errStream := ChatStream(context.Background(), "", ChatRequest{
		Credential: testCredential(),
		Profile:    cfg,
		Body:       []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`),
	}, func(chunk []byte) error {
		var m map[string]any
		if err := json.Unmarshal(chunk, &m); err != nil {
			t.Fatalf("chunk 非法: %v", err)
		}
		chunks = append(chunks, m)
		return nil
	})
	if errStream != nil {
		t.Fatalf("ChatStream: %v", errStream)
	}

	var firstCall, secondCall map[string]any
	var finishAny any
	for _, m := range chunks {
		choices, _ := m["choices"].([]any)
		if len(choices) == 0 {
			continue
		}
		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		if _, has := delta["function_call"]; has {
			t.Errorf("delta 不得残留上游 function_call 命名: %v", delta)
		}
		if tcs, ok := delta["tool_calls"].([]any); ok && len(tcs) > 0 {
			call, _ := tcs[0].(map[string]any)
			if _, hasID := call["id"]; hasID {
				if firstCall == nil {
					firstCall = call
				} else if secondCall == nil {
					secondCall = call
				}
			} else if secondCall == nil && firstCall != nil {
				secondCall = call
			}
		}
		if fr := choice["finish_reason"]; fr != nil {
			finishAny = fr
		}
	}
	if firstCall == nil || secondCall == nil {
		t.Fatalf("应收到两个 tool_calls delta, first=%v second=%v", firstCall, secondCall)
	}
	if firstCall["id"] != "call_x1" || firstCall["type"] != "function" || firstCall["index"] != float64(0) {
		t.Errorf("首个调用元数据错误: %v", firstCall)
	}
	fn1, _ := firstCall["function"].(map[string]any)
	if fn1["name"] != "Bash" || fn1["arguments"] != `{"command":"ls"}` {
		t.Errorf("首个调用 function 错误: %v", fn1)
	}
	if _, hasID := secondCall["id"]; hasID {
		t.Errorf("无 id 的增量块不应伪造 id 键: %v", secondCall)
	}
	fn2, _ := secondCall["function"].(map[string]any)
	if fn2["name"] != "" || fn2["arguments"] != " -la" {
		t.Errorf("增量块 function 错误: %v", fn2)
	}
	if finishAny != "tool_calls" {
		t.Errorf("finish_reason = %v, want tool_calls", finishAny)
	}
}

// TestChatAggregatesToolCallsIntoMessage 锁定非流式聚合：
// 按 index 合并 id/name/增量 arguments，输出升序、不带 index 键、finish_reason 透传。
func TestChatAggregatesToolCallsIntoMessage(t *testing.T) {
	stubHost(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case EpModels:
			_, _ = w.Write([]byte(catalogFixture))
		case EpChat:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(chatToolAggSSEFixture))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	body, errChat := Chat(context.Background(), "", ChatRequest{
		Credential: testCredential(),
		Profile:    cfg,
		Body:       []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`),
	})
	if errChat != nil {
		t.Fatalf("Chat: %v", errChat)
	}
	var got map[string]any
	if errJSON := json.Unmarshal(body, &got); errJSON != nil {
		t.Fatalf("decode response: %v", errJSON)
	}
	choices, _ := got["choices"].([]any)
	choice, _ := choices[0].(map[string]any)
	if choice["finish_reason"] != "tool_calls" {
		t.Errorf("finish_reason = %v, want tool_calls", choice["finish_reason"])
	}
	message, _ := choice["message"].(map[string]any)
	calls, okCalls := message["tool_calls"].([]any)
	if !okCalls || len(calls) != 2 {
		t.Fatalf("message.tool_calls = %v, want 长度 2", message["tool_calls"])
	}
	first, _ := calls[0].(map[string]any)
	if _, has := first["index"]; has {
		t.Errorf("非流式 tool_calls 项不应带 index 键: %v", first)
	}
	if first["id"] != "call_a" || first["type"] != "function" {
		t.Errorf("index 0 聚合错误: %v", first)
	}
	fn0, _ := first["function"].(map[string]any)
	if fn0["name"] != "Bash" || fn0["arguments"] != `{"command":"ls -la"}` {
		t.Errorf("index 0 arguments 未增量拼接: %v", fn0)
	}
	second, _ := calls[1].(map[string]any)
	fn1, _ := second["function"].(map[string]any)
	if second["id"] != "call_b" || fn1["name"] != "Read" || fn1["arguments"] != `{"path":"a.go"}` {
		t.Errorf("index 1 聚合错误: %v (function=%v)", second, fn1)
	}
}

func TestChatSurfacesUpstreamErrorEvent(t *testing.T) {
	stubHost(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case EpModels:
			_, _ = w.Write([]byte(catalogFixture))
		case EpChat:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: error\ndata: {\"code\":4023,\"message\":\"the model is unknown\"}\n\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	_, errChat := Chat(context.Background(), "", ChatRequest{
		Credential: testCredential(),
		Profile:    cfg,
		Body:       []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`),
	})
	if errChat == nil {
		t.Fatal("上游 error 事件应报错")
	}
	if !strings.Contains(errChat.Error(), "4023") {
		t.Errorf("错误信息未带上游码: %v", errChat)
	}
}

func TestChatRejectsModelOutsideCatalog(t *testing.T) {
	stubHost(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(catalogFixture))
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	_, errChat := Chat(context.Background(), "", ChatRequest{
		Credential: testCredential(),
		Profile:    cfg,
		Body:       []byte(`{"model":"not-a-model","messages":[{"role":"user","content":"hi"}]}`),
	})
	if errChat == nil {
		t.Fatal("目录外的模型应报错")
	}
	if !strings.Contains(errChat.Error(), "not-a-model") {
		t.Errorf("错误信息应点名模型: %v", errChat)
	}
}

// ---- 模型目录 ----

func TestFetchCatalogFiltersAndResolvesWireIDs(t *testing.T) {
	stubHost(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("get_detail_param 应为 POST，收到 %s", r.Method)
		}
		_, _ = w.Write([]byte(catalogFixture))
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)
	cred := testCredential()

	// 清掉可能存在的缓存，保证本用例独立。
	models, errModels := FetchModels(context.Background(), cred, cfg)
	if errModels != nil {
		t.Fatalf("FetchModels: %v", errModels)
	}
	ids := map[string]bool{}
	for _, model := range models {
		ids[model.ID] = true
	}
	if !ids["glm-5.2"] || !ids["DeepSeek-V4-Pro"] || !ids["deepseek-v4.1-flash"] {
		t.Errorf("可选对话模型缺失: %v", ids)
	}
	if ids["custom_model_gpt-5"] {
		t.Error("usage=custom_model 的路由配置不应出现在清单")
	}
	if ids["glm-5-off"] {
		t.Error("config_switch=false 的模型不应出现在清单")
	}

	resolved, errResolve := (&catalogCache{}).resolve(context.Background(), "DeepSeek-V4-Pro", cfg, cred)
	if errResolve != nil {
		t.Fatalf("catalog.resolve: %v", errResolve)
	}
	if resolved.ConfigName != "DeepSeek-V4-Pro" || resolved.WireName != "DeepSeek-V4-Pro__dev" {
		t.Errorf("解析结果不对: %+v", resolved)
	}

	// 大小写不敏感匹配，返回目录里的精确拼写。
	resolvedLower, errLower := (&catalogCache{}).resolve(context.Background(), "deepseek-v4-pro", cfg, cred)
	if errLower != nil {
		t.Fatalf("catalog.resolve(lower): %v", errLower)
	}
	if resolvedLower.ConfigName != "DeepSeek-V4-Pro" {
		t.Errorf("小写请求应归一到目录精确拼写: %+v", resolvedLower)
	}
}

// TestFetchCatalogUsesChatFunction 锁定目录请求的 function 必须与对话侧一致。
//
// 上游按 function 维护两套 wire id 命名空间：目录若取了另一套（如
// solo_work_lite 的 deepseek_v4_pro__dev）再发 chat_v3 对话，会被判
// 4023 model is unknown。
func TestFetchCatalogUsesChatFunction(t *testing.T) {
	stubHost(t)
	var gotBody map[string]any
	var gotHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(catalogFixture))
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)
	cfg.Function = "chat_v3"

	// nil 缓存：本次调用直接打上游，不受其它用例留下的条目影响。
	if _, errModels := FetchModels(context.Background(), testCredential(), cfg); errModels != nil {
		t.Fatalf("FetchModels: %v", errModels)
	}
	if gotBody["function"] != "chat_v3" {
		t.Errorf("目录请求体 function = %v，应跟随 cfg.Function", gotBody["function"])
	}
	for _, key := range []string{"X-App-Function", "X-Ide-Function"} {
		if got := gotHeaders.Get(key); got != "chat_v3" {
			t.Errorf("%s = %q，应跟随 cfg.Function", key, got)
		}
	}
}

// TestConfigureOverridesIDEVersion 锁定版本号可被配置覆盖，且按实例 ID 隔离。
func TestConfigureOverridesIDEVersion(t *testing.T) {
	cfg := ConfigFor(RegionCN)
	inst := &adapter{config: cfg}

	inst.Configure(core.Settings{}, map[string]string{
		"traecn_ide_version":      "9.9.9",
		"traecn_ide_version_code": "20990101",
		// 族级键与其它实例的键都不能生效。
		"trae_ide_version":       "1.1.1",
		"traeglobal_ide_version": "2.2.2",
	})
	if got := inst.profile(); got.IDEVersion != "9.9.9" || got.IDEVersionCode != "20990101" {
		t.Fatalf("覆盖未生效: %q / %q", got.IDEVersion, got.IDEVersionCode)
	}
	if inst.profile().Function != "chat_v3" || inst.profile().ChatHost != cfg.ChatHost {
		t.Error("覆盖版本号不应改动其它 profile 字段")
	}

	inst.Configure(core.Settings{}, map[string]string{})
	if got := inst.profile(); got.IDEVersion != IDEVersionCN || got.IDEVersionCode != IDEVersionCodeCN {
		t.Errorf("移除配置后应回落常量: %q / %q", got.IDEVersion, got.IDEVersionCode)
	}
}

// ---- 签到 ----

func checkinServer(t *testing.T, statusBody, claimBody string, claimStatus int) (*httptest.Server, *Config) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case EpCheckinStatus:
			_, _ = w.Write([]byte(statusBody))
		case EpCheckinClaim:
			w.WriteHeader(claimStatus)
			_, _ = w.Write([]byte(claimBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	cfg := testConfig(t, server.URL)
	return server, &cfg
}

func TestCheckinClaimsWhenNotCheckedIn(t *testing.T) {
	stubHost(t)
	_, cfg := checkinServer(t,
		`{"code":0,"enable":true,"checked_in":false,"credits":100}`,
		`{"code":0,"message":"success"}`, http.StatusOK)

	result, errCheckin := Checkin(context.Background(), testCredential(), *cfg)
	if errCheckin != nil {
		t.Fatalf("Checkin: %v", errCheckin)
	}
	if result.Already {
		t.Error("首次签到不应标记 Already")
	}
	if result.Credit != 100 {
		t.Errorf("Credit = %d, want 100", result.Credit)
	}
}

func TestCheckinSkipsWhenAlreadyCheckedIn(t *testing.T) {
	stubHost(t)
	claimed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case EpCheckinStatus:
			_, _ = w.Write([]byte(`{"code":0,"enable":true,"checked_in":true,"credits":100}`))
		case EpCheckinClaim:
			claimed = true
			_, _ = w.Write([]byte(`{"code":0,"message":"success"}`))
		}
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	result, errCheckin := Checkin(context.Background(), testCredential(), cfg)
	if errCheckin != nil {
		t.Fatalf("Checkin: %v", errCheckin)
	}
	if !result.Already {
		t.Error("已签到应标记 Already")
	}
	if claimed {
		t.Error("已签到时不应再发 claim（上游对重复签到也返回 code=0，无法区分）")
	}
}

func TestCheckinTreats9074AsBusy(t *testing.T) {
	stubHost(t)
	_, cfg := checkinServer(t,
		`{"code":0,"enable":true,"checked_in":false,"credits":100}`,
		`{"code":9074,"message":"too many users, retry later"}`, http.StatusOK)

	_, errCheckin := Checkin(context.Background(), testCredential(), *cfg)
	if errCheckin == nil {
		t.Fatal("9074 应报错")
	}
	failure, okFailure := errCheckin.(*core.Failure)
	if !okFailure {
		t.Fatalf("错误类型 = %T, want *core.Failure", errCheckin)
	}
	if failure.Kind != core.FailureKindBusy {
		t.Errorf("9074 应分类为 busy，得到 %q", failure.Kind)
	}
}

func TestCheckinDeviceIDIsStable(t *testing.T) {
	cred := testCredential()
	first := CheckinDeviceID(cred)
	if len(first) != 15 {
		t.Fatalf("device id 长度 = %d, want 15", len(first))
	}
	for _, char := range first {
		if char < '0' || char > '9' {
			t.Fatalf("device id 必须全是数字: %q", first)
		}
	}
	if second := CheckinDeviceID(cred); second != first {
		t.Errorf("device id 不稳定: %s vs %s", first, second)
	}
}

// ---- 额度 ----

func TestFetchQuotaSumsCreditPacks(t *testing.T) {
	stubHost(t)
	var gotPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != EpEntUsage {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("ide_user_ent_usage 应为 POST，收到 %s", r.Method)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotPayload)
		_, _ = w.Write([]byte(quotaFixture))
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	quota, errQuota := FetchQuota(context.Background(), testCredential(), cfg)
	if errQuota != nil {
		t.Fatalf("FetchQuota: %v", errQuota)
	}
	if gotPayload["require_usage"] != true {
		t.Errorf("require_usage = %v", gotPayload["require_usage"])
	}
	if gotPayload["req_source"] != float64(2) {
		t.Errorf("req_source = %v", gotPayload["req_source"])
	}
	values := map[string]float64{}
	for _, metric := range quota.Summary {
		values[metric.Key] = metric.Value
	}
	if values["credit_total"] != 4600 {
		t.Errorf("总额度 = %v, want 4600（product_type=0 的包不计）", values["credit_total"])
	}
	if values["credit_used"] != 0.4944 {
		t.Errorf("已用 = %v, want 0.4944", values["credit_used"])
	}
	if values["credit_remain"] != 4599.5056 {
		t.Errorf("剩余 = %v, want 4599.5056", values["credit_remain"])
	}
	if quota.Subscription == nil || quota.Subscription.Plan != "Trae 国内版权益" {
		t.Errorf("订阅信息不对: %+v", quota.Subscription)
	}
}

func TestFetchQuotaHandlesUnlimitedPack(t *testing.T) {
	stubHost(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"user_entitlement_pack_list":[
			{"entitlement_base_info":{"product_type":2,"quota":{"credits_limit":-1}},"usage":{"credits_amount":12.5}}
		]}`))
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	quota, errQuota := FetchQuota(context.Background(), testCredential(), cfg)
	if errQuota != nil {
		t.Fatalf("FetchQuota: %v", errQuota)
	}
	for _, metric := range quota.Summary {
		if metric.Key == "credit_remain" && (metric.Value != -1 || metric.Unit != "unlimited") {
			t.Errorf("无限额度剩余应标记 -1/unlimited，得到 %v/%s", metric.Value, metric.Unit)
		}
	}
}

// TestFetchQuotaGlobalUsesV1Endpoint 锁住国际版额度端点与区域头。
//
// 国际版额度路径是 v1（国内是 v2），且必须带 X-User-Region: SG / Package-Type:
// stable；这三处任一写错都会被网关当成跨区请求拒绝。本机同一账号改前 401/1001、
// 改后 200（期间也可能刷新过 token），这里只锁协议形态，不作为鉴权结论。
func TestFetchQuotaGlobalUsesV1Endpoint(t *testing.T) {
	stubHost(t)
	var gotPath, gotRegion, gotPackage string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotRegion = r.Header.Get("X-User-Region")
		gotPackage = r.Header.Get("Package-Type")
		_, _ = w.Write([]byte(`{"user_entitlement_pack_list":[
			{"entitlement_base_info":{"product_type":2,"quota":{"credits_limit":100}},"usage":{"credits_amount":25}}
		]}`))
	}))
	defer server.Close()

	cfg := ConfigFor(RegionGlobal)
	cfg.QuotaHost = server.URL
	cred := &Credential{
		Vendor:      VendorIDGlobal,
		Region:      RegionGlobal,
		AccessToken: "test-access-token",
		UID:         "2487573687317868",
	}

	quota, errQuota := FetchQuota(context.Background(), cred, cfg)
	if errQuota != nil {
		t.Fatalf("FetchQuota: %v", errQuota)
	}
	if gotPath != EpEntUsageGlobal {
		t.Fatalf("国际版额度路径 = %q, want %q", gotPath, EpEntUsageGlobal)
	}
	if gotRegion != "SG" {
		t.Fatalf("X-User-Region = %q, want SG", gotRegion)
	}
	if gotPackage != "stable" {
		t.Fatalf("Package-Type = %q, want stable", gotPackage)
	}
	values := map[string]float64{}
	for _, metric := range quota.Summary {
		values[metric.Key] = metric.Value
	}
	if values["credit_total"] != 100 || values["credit_used"] != 25 || values["credit_remain"] != 75 {
		t.Fatalf("国际版额度解析错误: %+v", values)
	}
}

// TestClientHeadersByRegion 锁住国内侧仍是 CN / stable_cn，避免只测国际版把
// 国内身份改坏。
func TestClientHeadersByRegion(t *testing.T) {
	cn := &Credential{Vendor: VendorIDCN, Region: RegionCN, AccessToken: "tok", UID: "42"}
	global := &Credential{Vendor: VendorIDGlobal, Region: RegionGlobal, AccessToken: "tok", UID: "42"}

	cnHeaders := checkinHeadersForUID(cn, "42")
	if cnHeaders["X-User-Region"] != "CN" || cnHeaders["Package-Type"] != "stable_cn" {
		t.Fatalf("国内版客户端头错误: region=%q package=%q", cnHeaders["X-User-Region"], cnHeaders["Package-Type"])
	}
	globalHeaders := checkinHeadersForUID(global, "42")
	if globalHeaders["X-User-Region"] != "SG" || globalHeaders["Package-Type"] != "stable" {
		t.Fatalf("国际版客户端头错误: region=%q package=%q", globalHeaders["X-User-Region"], globalHeaders["Package-Type"])
	}
}

// TestAllConfigsAreComplete 锁住 profile 表本身：额度端点与主机一旦漏填，
// 请求会打到 host+""，错误退化成费解的 URL 拼接失败。这类问题在表里能测出来，
// 就该在测试里挡住，而不是在构造函数里 panic。
func TestAllConfigsAreComplete(t *testing.T) {
	for _, cfg := range AllConfigs() {
		if cfg.VendorID == "" || cfg.VendorName == "" || cfg.Region == "" {
			t.Fatalf("实例标识缺失: %+v", cfg)
		}
		for name, value := range map[string]string{
			"ChatHost":    cfg.ChatHost,
			"AuthHost":    cfg.AuthHost,
			"RefreshHost": cfg.RefreshHost,
			"QuotaHost":   cfg.QuotaHost,
			"QuotaPath":   cfg.QuotaPath,
			"ConsoleHost": cfg.ConsoleHost,
			"IDEVersion":  cfg.IDEVersion,
		} {
			if value == "" {
				t.Fatalf("region %s 的 %s 为空", cfg.Region, name)
			}
		}
	}
	// 国内版有签到活动，国际版没有：这条差异必须显式留在表里。
	if cfg := ConfigFor(RegionCN); cfg.CheckinHost == "" {
		t.Fatal("国内版应有签到主机")
	}
	if cfg := ConfigFor(RegionGlobal); cfg.CheckinHost != "" {
		t.Fatal("国际版不应声明签到主机")
	}
}

// ---- 刷新 ----

func TestRefreshCredentialParsesResultEnvelope(t *testing.T) {
	stubHost(t)
	var gotPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != EpExchange {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotPayload)
		_, _ = w.Write([]byte(`{"Result":{"Token":"new-access","RefreshToken":"new-refresh","TokenExpireAt":1793613527094,"TokenExpireDuration":7200}}`))
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	updated, changed, errRefresh := RefreshCredential(context.Background(), testCredential(), cfg)
	if errRefresh != nil {
		t.Fatalf("RefreshCredential: %v", errRefresh)
	}
	if !changed {
		t.Error("应报告已变更")
	}
	if updated.AccessToken != "new-access" {
		t.Errorf("access token = %q", updated.AccessToken)
	}
	if updated.RefreshToken != "new-refresh" {
		t.Errorf("refresh token = %q", updated.RefreshToken)
	}
	// 毫秒时间戳归一为秒。
	if updated.ExpiresAt != 1793613527 {
		t.Errorf("expires_at = %d, want 1793613527", updated.ExpiresAt)
	}
	// PascalCase 载荷。
	if gotPayload["ClientID"] != ClientIDCN {
		t.Errorf("ClientID = %v, want %s", gotPayload["ClientID"], ClientIDCN)
	}
	if gotPayload["RefreshToken"] != "test-refresh-token" {
		t.Errorf("RefreshToken = %v", gotPayload["RefreshToken"])
	}
	if gotPayload["ClientSecret"] != "-" {
		t.Errorf("ClientSecret = %v", gotPayload["ClientSecret"])
	}
}

func TestRefreshCredentialFallsBackToDuration(t *testing.T) {
	stubHost(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Result":{"Token":"new-access","TokenExpireAt":0,"TokenExpireDuration":7200}}`))
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)

	updated, changed, errRefresh := RefreshCredential(context.Background(), testCredential(), cfg)
	if errRefresh != nil || !changed {
		t.Fatalf("RefreshCredential: changed=%v err=%v", changed, errRefresh)
	}
	if updated.ExpiresAt <= 0 {
		t.Errorf("TokenExpireAt 缺失时应由 duration 推导，得到 %d", updated.ExpiresAt)
	}
}

// ---- JWT 身份 ----

func TestJWTIdentityExtractsAccountID(t *testing.T) {
	// {"data":{"id":"2487573687317868"}} 的 JWT 中段（base64url）。
	token := "eyJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoiMjQ4NzU3MzY4NzMxNzg2OCJ9LCJleHAiOjE3OTM2MTM1Mjd9.sig"
	if got := jwtIdentity(token); got != "2487573687317868" {
		t.Errorf("jwtIdentity = %q, want 2487573687317868", got)
	}
	if got := jwtIdentity("not-a-jwt"); got != "" {
		t.Errorf("非 JWT 应返回空，得到 %q", got)
	}
}
