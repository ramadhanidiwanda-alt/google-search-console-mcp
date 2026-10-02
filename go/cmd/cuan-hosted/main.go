// Copyright 2026 Cuan Insight contributors. Licensed under the MIT License.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var connectionKey = regexp.MustCompile(`^ci_mcp_ck_[0-9a-f]{64}$`)

type keyContext struct{}

func keyFrom(ctx context.Context) string { key, _ := ctx.Value(keyContext{}).(string); return key }
func result(value any) (*mcp.CallToolResult, any, error) {
	b, e := json.Marshal(value)
	if e != nil {
		return nil, nil, errors.New("RESULT_UNAVAILABLE")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}
func addTools(srv *mcp.Server, s *service) {
	for _, name := range []string{"google_search_console_list_sites", "google_search_console_search_analytics", "google_search_console_preview_submit_sitemap", "google_search_console_submit_sitemap"} {
		toolName := name
		mcp.AddTool(srv, &mcp.Tool{Name: toolName, Description: "Cuan-admitted Search Console operation."},
			func(ctx context.Context, _ *mcp.CallToolRequest, in unifiedInput) (*mcp.CallToolResult, any, error) {
				if keyFrom(ctx) != "" || s.Unified == nil {
					return nil, nil, errDenied
				}
				v, err := s.Unified.invoke(ctx, toolName, in)
				if err != nil {
					return nil, nil, err
				}
				return result(v)
			})
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "search_analytics", Description: "Read at most 100 rows over at most 31 days from one exact Cuan-granted Search Console property."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in analyticsInput) (*mcp.CallToolResult, any, error) {
			v, e := s.analytics(ctx, keyFrom(ctx), in)
			if e != nil {
				return nil, nil, e
			}
			return result(v)
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "preview_submit_sitemap", Description: "Preview one same-site XML sitemap on a Cuan-granted owned disposable test property."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in previewInput) (*mcp.CallToolResult, any, error) {
			v, e := s.preview(ctx, keyFrom(ctx), in)
			if e != nil {
				return nil, nil, e
			}
			return result(v)
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "submit_sitemap", Description: "Submit one previewed sitemap after explicit confirmation and Cuan one-time claim."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in submitInput) (*mcp.CallToolResult, any, error) {
			v, e := s.submit(ctx, keyFrom(ctx), in)
			if e != nil {
				return nil, nil, e
			}
			return result(v)
		})
}
func buildHandler(srv *mcp.Server, allowedHost, ingressSecret string) http.Handler {
	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{Stateless: true})
	protection := http.NewCrossOriginProtection()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/mcp" || r.Method != http.MethodPost || r.Host != allowedHost ||
			len(r.Header.Values("x-cuan-search-console-ingress-secret")) != 1 ||
			len(r.Header.Values("x-cuan-mcp-connection-key")) > 1 ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get("x-cuan-search-console-ingress-secret")), []byte(ingressSecret)) != 1 ||
			(r.Header.Get("x-cuan-mcp-connection-key") != "" && !connectionKey.MatchString(r.Header.Get("x-cuan-mcp-connection-key"))) ||
			r.ContentLength < 1 || r.ContentLength > 65536 {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		key := r.Header.Get("x-cuan-mcp-connection-key")
		protection.Handler(http.MaxBytesHandler(transport, 65536)).ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyContext{}, key)))
	})
}
func required(name string, min int) string {
	value := os.Getenv(name)
	if len(value) < min {
		panic(name + " is missing or too short")
	}
	return value
}
func main() {
	endpoint := required("CUAN_SEARCH_CONSOLE_RUNTIME_URL", 9)
	if !strings.HasPrefix(endpoint, "https://") {
		panic("CUAN_SEARCH_CONSOLE_RUNTIME_URL requires HTTPS")
	}
	serviceID := required("SEARCH_CONSOLE_PRIVATE_SERVICE_ID", 1)
	if len(serviceID) > 128 {
		panic("SEARCH_CONSOLE_PRIVATE_SERVICE_ID too long")
	}
	serviceSecret := required("SEARCH_CONSOLE_PRIVATE_SERVICE_SECRET", 32)
	ingressSecret := required("SEARCH_CONSOLE_INGRESS_SECRET", 32)
	signingSecret := required("SEARCH_CONSOLE_PREVIEW_SIGNING_SECRET", 32)
	allowedHost := required("SEARCH_CONSOLE_MCP_ALLOWED_HOST", 1)
	if strings.ContainsAny(allowedHost, "/* ") {
		panic("SEARCH_CONSOLE_MCP_ALLOWED_HOST must be exact")
	}
	port := 8080
	if value := os.Getenv("PORT"); value != "" {
		parsed, e := strconv.Atoi(value)
		if e != nil || parsed < 1 || parsed > 65535 {
			panic("PORT invalid")
		}
		port = parsed
	}
	cuanClient := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	googleHTTP := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	s := &service{Authority: &cuanAuthority{Endpoint: endpoint, ServiceID: serviceID, ServiceSecret: serviceSecret, Client: cuanClient}, Google: &googleClient{Client: googleHTTP, Base: apiBase}, SigningSecret: []byte(signingSecret)}
	redeemURL := os.Getenv("CUAN_SEARCH_CONSOLE_REDEEM_URL")
	if redeemURL == "" {
		redeemURL = endpoint[:strings.LastIndex(endpoint, "/")] + "/mcp-redeem-google-permit"
	}
	if redeemURL != "" {
		if !strings.HasPrefix(redeemURL, "https://") {
			panic("CUAN_SEARCH_CONSOLE_REDEEM_URL requires HTTPS")
		}
		s.Unified = &unifiedService{Endpoint: redeemURL, ServiceID: serviceID, ServiceSecret: serviceSecret, Client: cuanClient, Google: s.Google}
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "cuan-search-console-mcp", Version: "0.1.0"}, nil)
	addTools(srv, s)
	handler := buildHandler(srv, allowedHost, ingressSecret)
	httpServer := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	slog.Info("Cuan Search Console MCP listening", "port", port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
