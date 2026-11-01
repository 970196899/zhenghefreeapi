package codearts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
	"freetier2api-plugin/internal/logger"
)

// defaultCredentialTTL 是解析不出上游过期时间时的兜底有效期。
//
// 上游 STS 临时凭据实际 TTL 约 2 小时，这里取 110 分钟留出余量。兜底值
// 必须贴近真实 TTL：宿主据此判断凭证是否过期，填得过大（如 12 小时）会让
// 已过期的凭证被当成「还活着」而跳过保活，直到真正用到才 401。
const defaultCredentialTTL = 110 * time.Minute

// pendingLogin 是一次进行中的 CodeArts 登录。
type pendingLogin struct {
	// TicketID 由本插件生成，授权链接与后续票据查询都用它。
	//
	// **不能**被回调里的 ticket_id 覆盖：门户回调里那个是它自己的中间票，
	// 拿它去查票据接口会被判「无效ticketId」（实测 TM.00001001）。
	TicketID string
	// Secret 初始是自造值；收到浏览器回调后换成门户下发的那个。
	Secret string
	// TicketFallback 标记「门户 secret 已就位」。之前不查票据接口——用自造
	// secret 查只会一直拿到无效票据，白白轮询。
	TicketFallback bool
	Verifier       string
	DPoPPrivateKey map[string]string
	// TicketURL 仅供单测注入票据端点；空表示 SnapManagerHost+EpLoginTicket。
	TicketURL string
}

// LoginStart 发起华为云 CodeArts 授权登录。
func LoginStart(ctx context.Context, logins core.LoginSessions) (*pluginapi.AuthLoginStartResponse, error) {
	ticketID := core.RandomHex(16)
	secret := core.RandomHex(16)
	verifier, challenge, errPKCE := core.NewPKCEPair()
	if errPKCE != nil {
		return nil, fmt.Errorf("generate pkce: %w", errPKCE)
	}
	dpopJWK, err := generateDPoPJWK()
	if err != nil {
		return nil, fmt.Errorf("generate dpop jwk: %w", err)
	}

	sessionID := "codearts_" + core.RandomHex(8)
	logins.Register(VendorID, sessionID, 15*time.Minute, 0, &pendingLogin{
		TicketID:       ticketID,
		Secret:         secret,
		Verifier:       verifier,
		DPoPPrivateKey: dpopJWK,
	})

	return &pluginapi.AuthLoginStartResponse{
		Provider:  "freetier",
		URL:       buildAuthorizeURL(ticketID, challenge),
		State:     sessionID,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

// buildAuthorizeURL 拼门户授权链接。
//
// 参数集与官方 CodeArts Agent 插件一致（逆向自 huaweicloud.authentication）：
// 关键在 port —— 门户按它拼出回调地址 http://127.0.0.1:<port>/oauth/callback。
// 少了这个参数，门户回落到默认端口，回调就打到 80 端口去了。
func buildAuthorizeURL(ticketID, challenge string) string {
	v := url.Values{}
	v.Set("theme", "2")
	v.Set("locale", "zh-cn")
	v.Set("uri_scheme", ClientID)
	v.Set("client_id", ClientID)
	v.Set("port", strconv.Itoa(LocalCallbackPort))
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "SHA-256")
	v.Set("ticket_id", ticketID)
	v.Set("plugin-name", PluginName)
	v.Set("plugin-version", PluginVersion)
	return PortalHost + "/authorize?" + v.Encode()
}

// LoginPoll 轮询华为云 ticket 登录结果。
func LoginPoll(ctx context.Context, logins core.LoginSessions, sessionID string) (*pluginapi.AuthLoginPollResponse, error) {
	session, pollState := logins.Poll(sessionID)
	if pollState == core.PollMissing {
		return &pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "登录会话不存在或已过期，请重新发起登录并在浏览器授权后立即粘贴回调链接",
		}, nil
	}
	pending, okPending := session.Data.(*pendingLogin)
	if !okPending {
		return &pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "登录会话数据已损坏，请重新发起登录",
		}, nil
	}
	return pollLoginTicket(ctx, logins, sessionID, pending)
}

// pollLoginTicket 用会话里当前的 ticket/secret 换一次凭证。
//
// ticket/secret 会被 SubmitCallback 换成「本插件的 ticket + 门户的 secret」，
// 因此普通轮询与粘贴回调共用这一段——区别只在「secret 从哪来」。
func pollLoginTicket(ctx context.Context, logins core.LoginSessions, sessionID string, pending *pendingLogin) (*pluginapi.AuthLoginPollResponse, error) {
	if !pending.TicketFallback {
		// 门户还没下发 secret：此刻查票据只会拿到「无效ticketId」，
		// 不是「用户在慢慢登录」。把两种等待分开，用户才知道下一步做什么。
		return &pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "等待浏览器完成华为云授权…完成后请把回调链接粘回控制台",
		}, nil
	}

	ticketURL := strings.TrimSpace(pending.TicketURL)
	if ticketURL == "" {
		ticketURL = SnapManagerHost + EpLoginTicket
	}
	result, errFetch := fetchTicketCredentials(ctx, ticketURL, pending.TicketID, pending.Secret)
	if errFetch != nil {
		return nil, core.ToPluginError(errFetch)
	}
	if !result.Ready {
		message := "等待用户在新的浏览器标签页里完成华为云登录…"
		if result.Note != "" {
			message += "（上游：" + result.Note + "）"
		}
		return &pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending, Message: message}, nil
	}

	logins.Delete(sessionID)
	return successResponse(result.Credentials, pending), nil
}

// successResponse 把票据/令牌返回的凭证转成宿主认识的登录成功响应。
func successResponse(creds *ticketCredentials, pending *pendingLogin) *pluginapi.AuthLoginPollResponse {
	uid := core.FirstNonEmpty(creds.UserID, creds.UserName, "codearts-user")
	expiresAt := parseExpiration(creds.Expiration)
	if expiresAt == 0 {
		expiresAt = time.Now().Add(defaultCredentialTTL).Unix()
	}
	cred := &Credential{
		Vendor:          VendorID,
		UserID:          creds.UserID,
		UserName:        creds.UserName,
		DomainID:        creds.DomainID,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SecurityToken:   creds.SecurityToken,
		RefreshToken:    creds.RefreshToken,
		CodeVerifier:    pending.Verifier,
		ClientID:        ClientID,
		DPoPPrivateKey:  pending.DPoPPrivateKey,
		Expiration:      creds.Expiration,
		ExpiresAt:       expiresAt,
		Label:           "CodeArts-" + uid,
	}
	storageJSON, errStorage := cred.StorageJSON()
	if errStorage != nil {
		return &pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: errStorage.Error()}
	}
	return &pluginapi.AuthLoginPollResponse{
		Status:  pluginapi.AuthLoginStatusSuccess,
		Message: "华为云账号登录成功",
		Auth: pluginapi.AuthData{
			Provider:    "freetier",
			FileName:    "codearts-" + uid + ".json",
			Label:       cred.Label,
			StorageJSON: storageJSON,
		},
	}
}

// ticketCredentials 是登录票据或令牌接口返回的临时凭证。
type ticketCredentials struct {
	UserName        string
	UserID          string
	DomainID        string
	RefreshToken    string
	AccessKeyID     string
	SecretAccessKey string
	SecurityToken   string
	Expiration      string
}

// ticketPollResult 是一次票据查询的结果。
type ticketPollResult struct {
	Credentials *ticketCredentials
	// Ready 表示上游已经下发可用的 AK/SK + security_token。
	Ready bool
	// Note 是上游原话（不含票据与密钥），用于回答「到底卡在哪一步」。
	Note string
}

// fetchTicketCredentials 用 ticket/secret 查登录票据，换 AK/SK。
//
// 上游一律用「没准备好」回应未完成的授权（实测是 TM.00001001 无效ticketId，
// 与乱填的 ticket 得到的回答一样），所以这里一律当等待处理，不当成终态失败——
// 终态只由会话过期决定，用户重新发起即可。
func fetchTicketCredentials(ctx context.Context, ticketURL, ticketID, secret string) (ticketPollResult, error) {
	path := ticketURL + "?ticket_id=" + url.QueryEscape(ticketID) + "&secret=" + url.QueryEscape(secret)
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if errReq != nil {
		return ticketPollResult{}, errReq
	}
	req.Header.Set("plugin-name", PluginName)
	req.Header.Set("plugin-version", PluginVersion)

	client := hostbridge.Client(ctx, 30*time.Second)
	resp, errDo := client.Do(req)
	if errDo != nil {
		return ticketPollResult{}, fmt.Errorf("poll login ticket failed: %w", errDo)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		note := describeUpstream(resp.StatusCode, body)
		logger.Debug("codearts: 票据未就绪 %s", note)
		return ticketPollResult{Note: note}, nil
	}

	creds, errParse := decodeTokenResponse(body)
	if errParse != nil {
		return ticketPollResult{}, errParse
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SecurityToken == "" {
		return ticketPollResult{Note: describeUpstream(resp.StatusCode, body)}, nil
	}
	return ticketPollResult{Ready: true, Credentials: creds}, nil
}

// describeUpstream 把上游回应压成一句可展示的话。
//
// 优先取云厂商标准的 error_code / error_msg；非 JSON 正文截断到 160 字。
// 正文里不含票据与密钥（那是请求参数），可以安全展示给用户。
func describeUpstream(status int, body []byte) string {
	var envelope struct {
		Code string `json:"error_code"`
		Msg  string `json:"error_msg"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && (envelope.Msg != "" || envelope.Code != "") {
		joined := core.FirstNonEmpty(envelope.Msg, envelope.Code)
		if envelope.Code != "" && envelope.Msg != "" {
			joined = envelope.Code + " " + envelope.Msg
		}
		return "HTTP " + strconv.Itoa(status) + " " + joined
	}
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 160 {
		trimmed = trimmed[:160] + "…"
	}
	if trimmed == "" {
		return "HTTP " + strconv.Itoa(status)
	}
	return "HTTP " + strconv.Itoa(status) + " " + trimmed
}

// CallbackInfo 是华为云 localhost 回调里带回来的信息。
type CallbackInfo struct {
	// TicketID 是回调里那个 URL 所携带的票据号（门户中间票，**不是**本会话的票）。
	TicketID string
	// Secret 是门户下发的票据密钥：要拿它替换本会话自造的 secret。
	Secret string
	// Code 是 OAuth2 授权码（较新的门户会带；带它就不必再走票据通道）。
	Code string
	// Redirect 是用户接下来要在浏览器里打开的门户登录页。
	Redirect string
}

// ParseCallback 解析用户粘贴的 localhost 回调链接。
//
// 两种形态：
//
//	旧票据通道：http://127.0.0.1:7866/oauth/callback?secret=<门户密钥>&
//		redirect=<门户登录页?...&ticket_id=<票据号>&...>
//
//	新授权码通道：http://127.0.0.1:7866/oauth/callback?code=<授权码>
//
// 只接受回环地址与该路径：别的地址不是本次登录的回调，粘错了不该改会话状态。
func ParseCallback(rawURL string) (*CallbackInfo, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("empty callback url")
	}
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "http://127.0.0.1" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse callback url: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "http") || !isLoopbackHost(u.Hostname()) || u.Path != LocalCallbackPath {
		return nil, fmt.Errorf("不是本机回调地址（应为 http://127.0.0.1<port>%s）", LocalCallbackPath)
	}

	q := u.Query()
	info := &CallbackInfo{
		Code:     strings.TrimSpace(q.Get("code")),
		Secret:   strings.TrimSpace(q.Get("secret")),
		Redirect: strings.TrimSpace(q.Get("redirect")),
	}
	if info.Redirect != "" {
		if portal, errPortal := url.Parse(info.Redirect); errPortal == nil {
			info.TicketID = strings.TrimSpace(portal.Query().Get("ticket_id"))
		}
	}
	// 两种可用形态：授权码，或「secret + 门户登录页」。
	// 只有 secret 没有 redirect 时无法核对票据号，不敢认领——宁可让用户重发。
	if info.Code == "" && (info.Secret == "" || info.Redirect == "") {
		return nil, fmt.Errorf("回调链接里既没有 code，也没有 secret + redirect")
	}
	return info, nil
}

// isLoopbackHost 报告 host 是否是本机回环地址。
func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// SubmitCallback 接受用户粘贴的 localhost 回调链接。
//
// 浏览器跳回 127.0.0.1 时，插件与浏览器不在同一台机器（远程主机 / Docker /
// WSL）就收不到这条回调，登录会永远停在等待。用户把地址栏里的整条链接粘回来，
// 这里就地续完登录：
//
//   - 带 code：直接用授权码换 STS 凭证，一次到位；
//   - 带 secret/redirect：记下门户下发的 secret（**保留本会话自己的 ticket_id**），
//     再查一次票据；用户点开 redirect 完成授权后，后续轮询就会换到凭证。
func SubmitCallback(ctx context.Context, logins core.LoginSessions, state, rawURL string) (*core.CallbackSubmitResult, error) {
	sessionID := strings.TrimSpace(state)
	if sessionID == "" {
		return nil, core.NewPluginError("invalid_request", "缺少登录会话 state，请重新发起登录", http.StatusBadRequest)
	}
	session, pollState := logins.Poll(sessionID)
	if pollState == core.PollMissing {
		return nil, core.NewPluginError("session_not_found",
			"登录会话不存在或已过期，请重新发起登录并在浏览器授权后立即粘贴回调链接", http.StatusNotFound)
	}
	pending, okPending := session.Data.(*pendingLogin)
	if !okPending {
		return nil, core.NewPluginError("login_session_broken", "登录会话数据已损坏，请重新发起登录", http.StatusBadRequest)
	}

	// 解析失败时不回显原始链接：里面带着票据密钥与授权码。
	info, errParse := ParseCallback(rawURL)
	if errParse != nil {
		return nil, core.NewPluginError("callback_parse_failed",
			"回调链接解析失败，请确认粘贴的是浏览器地址栏里的完整链接（本机 127.0.0.1 开头、路径 /oauth/callback）",
			http.StatusBadRequest)
	}

	if info.Code != "" {
		creds, errExchange := exchangeAuthorizationCode(ctx, info.Code, pending)
		if errExchange != nil {
			return nil, core.ToPluginError(errExchange)
		}
		logins.Delete(sessionID)
		polled := successResponse(creds, pending)
		return &core.CallbackSubmitResult{
			Status: polled.Status, Message: polled.Message, Auth: polled.Auth,
		}, nil
	}

	// 票据通道：门户 secret 才是能用的那把，ticket_id 仍用本会话的。
	if info.TicketID != "" && pending.TicketID != "" && info.TicketID != pending.TicketID {
		return nil, core.NewPluginError("callback_mismatch",
			"回调链接里的票据号与当前登录会话不一致，请重新发起登录后重新授权", http.StatusBadRequest)
	}
	pending.Secret = info.Secret
	pending.TicketFallback = true

	polled, errPoll := pollLoginTicket(ctx, logins, sessionID, pending)
	if errPoll != nil {
		return nil, core.ToPluginError(errPoll)
	}
	result := &core.CallbackSubmitResult{Status: polled.Status, Message: polled.Message}
	if polled.Status == pluginapi.AuthLoginStatusSuccess {
		result.Auth = polled.Auth
		return result, nil
	}
	//票据还没换到凭证：把门户登录页交给用户去完成授权，插件继续轮询。
	result.RedirectURL = info.Redirect
	return result, nil
}

// exchangeAuthorizationCode 用 OAuth2 授权码换 STS 凭证。
func exchangeAuthorizationCode(ctx context.Context, code string, pending *pendingLogin) (*ticketCredentials, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", ClientID)
	form.Set("code", code)
	form.Set("code_verifier", pending.Verifier)
	form.Set("redirect_uri", LocalCallbackURL)
	return requestTokenCredentials(ctx, form, pending.DPoPPrivateKey)
}

func generateDPoPJWK() (map[string]string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pad := func(b *big.Int, sz int) []byte {
		buf := make([]byte, sz)
		raw := b.Bytes()
		copy(buf[sz-len(raw):], raw)
		return buf
	}
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(pad(key.PublicKey.X, 32)),
		"y":   base64.RawURLEncoding.EncodeToString(pad(key.PublicKey.Y, 32)),
		"d":   base64.RawURLEncoding.EncodeToString(pad(key.D, 32)),
	}, nil
}

// requestTokenCredentials 向 STS 令牌端点提交表单（带 DPoP 证明）并解析凭证。
//
// 授权码换 token 与 refresh_token 续期是同一个端点的两种 grant_type，共用这一份
// 请求与解析逻辑：DPoP 私钥是绑定的，两条通道必须用同一把，否则上游拒。
func requestTokenCredentials(ctx context.Context, form url.Values, dpopJWK map[string]string) (*ticketCredentials, error) {
	tokenURL := STSHost + EpOAuthTokens
	proof, errProof := buildDPoPProof(dpopJWK, tokenURL)
	if errProof != nil {
		return nil, fmt.Errorf("build dpop proof: %w", errProof)
	}

	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if errReq != nil {
		return nil, errReq
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)

	client := hostbridge.Client(ctx, 30*time.Second)
	resp, errDo := client.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("token request failed: %w", errDo)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, Classify(resp.StatusCode, string(body))
	}
	creds, errParse := decodeTokenResponse(body)
	if errParse != nil {
		return nil, errParse
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SecurityToken == "" {
		return nil, fmt.Errorf("token response missing credentials")
	}
	return creds, nil
}

// decodeTokenResponse 解析令牌/票据响应。
//
// 上游有两种字段形态：新通道用 credentials.{access_key_id, secret_access_key,
// security_token}，旧的票据通道用 credential.{access, secret, securitytoken}。
// 两种都认，否则升级后凭证字段读空。
func decodeTokenResponse(body []byte) (*ticketCredentials, error) {
	var res struct {
		UserName     string `json:"user_name"`
		UserID       string `json:"user_id"`
		DomainID     string `json:"domain_id"`
		RefreshToken string `json:"refresh_token"`
		Credential   struct {
			Access        string `json:"access"`
			Secret        string `json:"secret"`
			SecurityToken string `json:"securitytoken"`
			ExpiresAt     string `json:"expires_at"`
		} `json:"credential"`
		Credentials struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
			SecurityToken   string `json:"security_token"`
			Expiration      string `json:"expiration"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return &ticketCredentials{
		UserName:        res.UserName,
		UserID:          res.UserID,
		DomainID:        res.DomainID,
		RefreshToken:    res.RefreshToken,
		AccessKeyID:     core.FirstNonEmpty(res.Credentials.AccessKeyID, res.Credential.Access),
		SecretAccessKey: core.FirstNonEmpty(res.Credentials.SecretAccessKey, res.Credential.Secret),
		SecurityToken:   core.FirstNonEmpty(res.Credentials.SecurityToken, res.Credential.SecurityToken),
		Expiration:      core.FirstNonEmpty(res.Credentials.Expiration, res.Credential.ExpiresAt),
	}, nil
}

// RefreshCredential 用 refresh_token 换新的 STS 凭证。
//
// DPoP 私钥与 refresh_token 是绑定的：必须用签发它的那一把，否则上游报
// InvalidDPoPHeader，表现为「凭证失效」而被错误停用。
func RefreshCredential(ctx context.Context, cred *Credential) (*Credential, bool, error) {
	if cred == nil || cred.RefreshToken == "" {
		return cred, false, nil
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", core.FirstNonEmpty(cred.ClientID, ClientID))
	form.Set("refresh_token", cred.RefreshToken)
	if cred.CodeVerifier != "" {
		form.Set("code_verifier", cred.CodeVerifier)
	}

	creds, errRefresh := requestTokenCredentials(ctx, form, cred.DPoPPrivateKey)
	if errRefresh != nil {
		return nil, false, errRefresh
	}

	updated := *cred
	updated.AccessKeyID = creds.AccessKeyID
	updated.SecretAccessKey = creds.SecretAccessKey
	updated.SecurityToken = creds.SecurityToken
	if creds.RefreshToken != "" {
		updated.RefreshToken = creds.RefreshToken
	}
	if creds.Expiration != "" {
		updated.Expiration = creds.Expiration
		if exp := parseExpiration(creds.Expiration); exp > 0 {
			updated.ExpiresAt = exp
		}
	}
	if updated.ExpiresAt == 0 {
		updated.ExpiresAt = time.Now().Add(defaultCredentialTTL).Unix()
	}
	return &updated, true, nil
}

// MergeStorageJSON 合并续期凭证。
func MergeStorageJSON(original []byte, updated *Credential) ([]byte, error) {
	if updated == nil {
		return original, nil
	}
	return core.MergeCredentialJSON(original, updated.StorageJSON, func(m map[string]any) {
		m["access_key_id"] = updated.AccessKeyID
		m["secret_access_key"] = updated.SecretAccessKey
		m["security_token"] = updated.SecurityToken
		if updated.RefreshToken != "" {
			m["refresh_token"] = updated.RefreshToken
		}
		if updated.Expiration != "" {
			m["expiration"] = updated.Expiration
		}
		if updated.ExpiresAt > 0 {
			m["expires_at"] = updated.ExpiresAt
		}
	})
}

func buildDPoPProof(jwk map[string]string, htu string) (string, error) {
	if jwk == nil || jwk["d"] == "" {
		return "", fmt.Errorf("missing dpop private key material")
	}

	dRaw, errD := base64.RawURLEncoding.DecodeString(jwk["d"])
	if errD != nil {
		return "", fmt.Errorf("decode dpop jwk base64 failed")
	}

	curve := elliptic.P256()
	pad := func(val *big.Int, sz int) []byte {
		buf := make([]byte, sz)
		raw := val.Bytes()
		copy(buf[sz-len(raw):], raw)
		return buf
	}

	var privKey *ecdsa.PrivateKey
	xStr := jwk["x"]
	yStr := jwk["y"]
	if xStr == "" || yStr == "" {
		x, y := curve.ScalarBaseMult(dRaw)
		xStr = base64.RawURLEncoding.EncodeToString(pad(x, 32))
		yStr = base64.RawURLEncoding.EncodeToString(pad(y, 32))
		jwk["x"] = xStr
		jwk["y"] = yStr
		privKey = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
			D: new(big.Int).SetBytes(dRaw),
		}
	} else {
		xRaw, errX := base64.RawURLEncoding.DecodeString(xStr)
		yRaw, errY := base64.RawURLEncoding.DecodeString(yStr)
		if errX != nil || errY != nil {
			return "", fmt.Errorf("decode dpop jwk base64 failed")
		}
		privKey = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     new(big.Int).SetBytes(xRaw),
				Y:     new(big.Int).SetBytes(yRaw),
			},
			D: new(big.Int).SetBytes(dRaw),
		}
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   xStr,
			"y":   yStr,
		},
	}
	headerJSON, _ := json.Marshal(header)

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	jti := hex.EncodeToString(b)

	payload := map[string]any{
		"htm": "POST",
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": jti,
	}
	payloadJSON, _ := json.Marshal(payload)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))

	r, s, errSign := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if errSign != nil {
		return "", errSign
	}

	// 归一化为低 S
	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(n, s)
	}

	sigBytes := append(pad(r, 32), pad(s, 32)...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes), nil
}
