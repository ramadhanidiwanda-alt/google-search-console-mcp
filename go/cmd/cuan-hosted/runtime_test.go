package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const testKey = "ci_mcp_ck_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testSite = "https://example.com/"
const testMap = "https://example.com/sitemap.xml"

func TestUnifiedPermitBindsExactBytesAndWritesOnce(t *testing.T) {
	resourceHash := sha256.Sum256([]byte(testSite))
	resourceID := hex.EncodeToString(resourceHash[:])
	redemptions := 0
	finalizations := 0
	redeemer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-cuan-mcp-connection-key") != "" || r.Header.Get("x-cuan-search-console-service-secret") != strings.Repeat("s", 32) {
			t.Fatal("redeem leaked caller key or lost service proof")
		}
		if strings.HasSuffix(r.URL.Path, "/mcp-finalize-execution") {
			finalizations++
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		redemptions++
		_, _ = w.Write([]byte(`{"ok":true,"provider":"search_console","resourceId":"` + resourceID + `","providerTarget":"` + testSite + `","accessToken":"ephemeral","previewId":"preview-123","approvalDigest":"` + strings.Repeat("a", 64) + `"}`))
	}))
	defer redeemer.Close()
	g := &fakeGoogle{}
	s := &unifiedService{Endpoint: redeemer.URL + "/functions/v1/mcp-redeem-google-permit", ServiceID: "service", ServiceSecret: strings.Repeat("s", 32), Client: redeemer.Client(), Google: g}
	canonical := `{"accountId":"` + resourceID + `","sitemapUrl":"` + testMap + `","confirmed":true,"previewId":"preview-123","approvalDigest":"` + strings.Repeat("a", 64) + `"}`
	d := sha256.Sum256([]byte(canonical))
	in := unifiedInput{GoogleInvocation: googleInvocation{Version: 1, PublicTool: "google_search_console_submit_sitemap", Provider: "search_console", ResourceID: resourceID, CanonicalArgumentsJSON: canonical, Digest: hex.EncodeToString(d[:]), ExecutionID: "execution_123", Permit: strings.Repeat("p", 43)}}
	changed := in
	changed.GoogleInvocation.CanonicalArgumentsJSON += " "
	if _, err := s.invoke(context.Background(), in.GoogleInvocation.PublicTool, changed); err == nil || redemptions != 0 || g.writes != 0 {
		t.Fatal("changed argument bytes reached redeem")
	}
	result, err := s.invoke(context.Background(), in.GoogleInvocation.PublicTool, in)
	if err != nil || result.(map[string]any)["status"] != "CONFIRMED" || redemptions != 1 || finalizations != 1 || g.writes != 1 {
		t.Fatalf("write not single-dispatched: %#v %v", result, err)
	}
}

type fakeAuthority struct {
	actions []string
	used    bool
	final   string
	deny    bool
}

func (a *fakeAuthority) Call(_ context.Context, key, action string, r authorityRequest) (credential, error) {
	if key != testKey || a.deny {
		return credential{}, errDenied
	}
	a.actions = append(a.actions, action)
	if action == "finalizeWrite" {
		a.final = r.Status
		return credential{Acknowledged: true}, nil
	}
	if action == "claimWrite" {
		if a.used {
			return credential{}, errDenied
		}
		a.used = true
	}
	return credential{SiteURL: r.SiteURL, RequestDigest: r.RequestDigest, ExecutionID: r.ExecutionID, SiteVerified: true, SiteOwner: true, DisposableTestSite: true, WriteClaimed: action == "claimWrite", Scope: writeScope, AccessToken: "ephemeral", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}, nil
}

type fakeGoogle struct {
	writes         int
	failedReadback bool
}

func (g *fakeGoogle) Do(_ context.Context, token, method, path string, body any) (map[string]any, error) {
	if token != "ephemeral" {
		return nil, errProvider
	}
	if strings.HasSuffix(path, "/searchAnalytics/query") {
		return map[string]any{"rows": []any{map[string]any{"keys": []any{"2026-09-30"}, "clicks": float64(2), "impressions": float64(10), "ctr": float64(.2), "position": float64(3)}}}, nil
	}
	if strings.HasSuffix(path, "/sitemaps") {
		if g.failedReadback && g.writes > 0 {
			return nil, errProvider
		}
		return map[string]any{"sitemap": []any{map[string]any{"path": testMap}}}, nil
	}
	if strings.Contains(path, "/sitemaps/") {
		if method == http.MethodPut {
			g.writes++
			return map[string]any{}, nil
		}
		if g.failedReadback {
			return nil, errProvider
		}
		return map[string]any{"path": testMap}, nil
	}
	return map[string]any{"siteUrl": testSite, "permissionLevel": "siteOwner"}, nil
}
func testService() (*service, *fakeAuthority, *fakeGoogle) {
	a := &fakeAuthority{}
	g := &fakeGoogle{}
	return &service{Authority: a, Google: g, SigningSecret: []byte(strings.Repeat("s", 32))}, a, g
}
func TestAnalyticsBoundedAndExact(t *testing.T) {
	s, a, _ := testService()
	value, err := s.analytics(context.Background(), testKey, analyticsInput{SiteURL: testSite, StartDate: "2026-09-30", EndDate: "2026-09-30"})
	if err != nil || len(value.(map[string]any)["rows"].([]any)) != 1 || len(a.actions) != 1 || a.actions[0] != "resolveRead" {
		t.Fatalf("analytics failed: %v %v", value, err)
	}
	for _, in := range []analyticsInput{{SiteURL: testSite, StartDate: "2026-01-01", EndDate: "2026-03-01"}, {SiteURL: "example.com", StartDate: "2026-09-30", EndDate: "2026-09-30"}, {SiteURL: testSite, StartDate: "2026-09-30", EndDate: "2026-09-30", RowLimit: 101}} {
		if _, err := s.analytics(context.Background(), testKey, in); err == nil {
			t.Fatalf("invalid analytics accepted: %#v", in)
		}
	}
	if len(a.actions) != 1 {
		t.Fatal("invalid reads contacted Cuan")
	}
}
func TestPreviewClaimFinalizeAndReplay(t *testing.T) {
	s, a, g := testService()
	value, err := s.preview(context.Background(), testKey, previewInput{SiteURL: testSite, SitemapURL: testMap})
	if err != nil {
		t.Fatal(err)
	}
	token := value.(map[string]any)["previewToken"].(string)
	if _, err := s.submit(context.Background(), testKey, submitInput{PreviewToken: token, Approved: false}); err == nil {
		t.Fatal("confirmation bypass")
	}
	if g.writes != 0 || a.used {
		t.Fatal("write before confirmation")
	}
	result, err := s.submit(context.Background(), testKey, submitInput{PreviewToken: token, Approved: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]any)["status"] != "CONFIRMED" || g.writes != 1 || a.final != "CONFIRMED" {
		t.Fatal("missing confirmed finalization")
	}
	if _, err := s.submit(context.Background(), testKey, submitInput{PreviewToken: token, Approved: true}); err == nil || g.writes != 1 {
		t.Fatal("replay dispatched")
	}
}
func TestUnknownOutcomePreservesClaim(t *testing.T) {
	s, a, g := testService()
	value, err := s.preview(context.Background(), testKey, previewInput{SiteURL: testSite, SitemapURL: testMap})
	if err != nil {
		t.Fatal(err)
	}
	g.failedReadback = true
	result, err := s.submit(context.Background(), testKey, submitInput{PreviewToken: value.(map[string]any)["previewToken"].(string), Approved: true})
	if err != nil || result.(map[string]any)["status"] != "UNKNOWN_OUTCOME" || a.final != "UNKNOWN_OUTCOME" || g.writes != 1 {
		t.Fatal("uncertain write was not preserved")
	}
}
func TestInvalidSitemapAndForgedPreview(t *testing.T) {
	s, a, g := testService()
	for _, target := range []string{"https://evil.com/sitemap.xml", "http://example.com/sitemap.xml", "https://example.com/sitemap.xml?x=1"} {
		if _, err := s.preview(context.Background(), testKey, previewInput{SiteURL: testSite, SitemapURL: target}); err == nil {
			t.Fatalf("unsafe sitemap accepted %s", target)
		}
	}
	if len(a.actions) != 0 {
		t.Fatal("unsafe target reached Cuan")
	}
	if _, err := s.submit(context.Background(), testKey, submitInput{PreviewToken: "forged", Approved: true}); err == nil || g.writes != 0 {
		t.Fatal("forged preview dispatched")
	}
}
func TestIngressRejectsBeforeMCP(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	svc, authority, _ := testService()
	addTools(srv, svc)
	handler := buildHandler(srv, "mcp.example.test", strings.Repeat("i", 32))
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	request := httptest.NewRequest(http.MethodPost, "http://mcp.example.test/mcp", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("x-cuan-mcp-connection-key", testKey)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 403 {
		t.Fatalf("missing secret status=%d", w.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "http://mcp.example.test/mcp", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("x-cuan-mcp-connection-key", testKey)
	request.Header.Set("x-cuan-search-console-ingress-secret", strings.Repeat("i", 32))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 200 {
		t.Fatalf("authenticated MCP init status=%d body=%s", w.Code, w.Body.String())
	}
	var response map[string]any
	message := strings.TrimSpace(strings.TrimPrefix(w.Body.String(), "event: message\ndata: "))
	if json.Unmarshal([]byte(message), &response) != nil || response["result"] == nil {
		t.Fatalf("MCP init failed: %s", w.Body.String())
	}
	call := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_analytics","arguments":{"site_url":"https://example.com/","start_date":"2026-09-30","end_date":"2026-09-30"}}}`)
	request = httptest.NewRequest(http.MethodPost, "http://mcp.example.test/mcp", bytes.NewReader(call))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("x-cuan-mcp-connection-key", testKey)
	request.Header.Set("x-cuan-search-console-ingress-secret", strings.Repeat("i", 32))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"result":{"content"`) || len(authority.actions) != 1 {
		t.Fatalf("MCP tool call lost key or failed: status=%d body=%s", w.Code, w.Body.String())
	}
	request.Host = "attacker.test"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 403 {
		t.Fatal("Host bypass")
	}
}
func TestCuanTransportRequiresProof(t *testing.T) {
	seen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		if r.Header.Get("x-cuan-mcp-connection-key") != testKey || r.Header.Get("x-cuan-search-console-service-id") != "svc" || r.Header.Get("x-cuan-search-console-service-secret") != strings.Repeat("s", 32) {
			t.Fatal("missing proofs")
		}
		_, _ = w.Write([]byte(`{"siteUrl":"https://example.com/"}`))
	}))
	defer server.Close()
	c := &cuanAuthority{Endpoint: server.URL, ServiceID: "svc", ServiceSecret: strings.Repeat("s", 32), Client: server.Client()}
	if _, err := c.Call(context.Background(), testKey, "resolveRead", authorityRequest{SiteURL: testSite}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(context.Background(), "bad", "resolveRead", authorityRequest{}); !errors.Is(err, errDenied) || seen != 1 {
		t.Fatal("bad key contacted Cuan")
	}
}
