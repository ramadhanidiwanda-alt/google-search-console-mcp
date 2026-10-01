// Copyright 2026 Cuan Insight contributors. Licensed under the MIT License.
// Hosted mode uses Cuan OAuth grants and never loads upstream service-account credentials.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const apiBase = "https://www.googleapis.com/webmasters/v3"
const readScope = "https://www.googleapis.com/auth/webmasters.readonly"
const writeScope = "https://www.googleapis.com/auth/webmasters"
const previewTTL = 5 * time.Minute

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var domain = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
var allowedDimensions = map[string]bool{"date": true, "page": true, "query": true, "country": true, "device": true}
var errInvalid = errors.New("INVALID_TARGET")
var errDenied = errors.New("AUTHORIZATION_MISMATCH")
var errProvider = errors.New("GOOGLE_API_UNAVAILABLE")

// canonicalJSON matches JavaScript JSON.stringify for these ASCII-bound inputs.
func canonicalJSON(value any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
func digest(value any) string {
	b, _ := canonicalJSON(value)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func siteIdentity(value string) (host, path, scheme string, err error) {
	if len(value) == 0 || len(value) > 512 {
		return "", "", "", errInvalid
	}
	if strings.HasPrefix(value, "sc-domain:") {
		host = strings.TrimPrefix(value, "sc-domain:")
		if !domain.MatchString(host) {
			return "", "", "", errInvalid
		}
		return host, "/", "", nil
	}
	u, e := url.Parse(value)
	if e != nil || u == nil || !(u.Scheme == "https" || u.Scheme == "http") || !domain.MatchString(u.Hostname()) || u.Port() != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(value, "?#") || strings.Contains(u.Path, "//") || strings.Contains(value, "%") || !strings.HasSuffix(u.Path, "/") || u.String() != value {
		return "", "", "", errInvalid
	}
	return u.Hostname(), u.Path, u.Scheme, nil
}
func sitemapTarget(siteURL, sitemapURL string) error {
	host, path, scheme, err := siteIdentity(siteURL)
	if err != nil {
		return err
	}
	if len(sitemapURL) == 0 || len(sitemapURL) > 1024 {
		return errInvalid
	}
	u, e := url.Parse(sitemapURL)
	if e != nil || u == nil || u.Scheme != "https" || !domain.MatchString(u.Hostname()) || u.Port() != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(sitemapURL, "?#%") || strings.Contains(u.Path, "//") || !strings.HasSuffix(u.Path, ".xml") || u.String() != sitemapURL {
		return errInvalid
	}
	if scheme != "" {
		if scheme != "https" || u.Hostname() != host || !strings.HasPrefix(u.Path, path) {
			return errInvalid
		}
	}
	if scheme == "" && u.Hostname() != host && !strings.HasSuffix(u.Hostname(), "."+host) {
		return errInvalid
	}
	return nil
}
func parseDate(value string) (time.Time, error) {
	if len(value) != 10 {
		return time.Time{}, errInvalid
	}
	d, e := time.Parse("2006-01-02", value)
	if e != nil || d.Format("2006-01-02") != value {
		return time.Time{}, errInvalid
	}
	return d, nil
}

type authorityRequest struct {
	Operation     string `json:"operation"`
	SiteURL       string `json:"siteUrl"`
	SitemapURL    string `json:"sitemapUrl,omitempty"`
	RequestDigest string `json:"requestDigest"`
	ExecutionID   string `json:"executionId"`
	Status        string `json:"status,omitempty"`
}
type credential struct {
	SiteURL            string `json:"siteUrl"`
	RequestDigest      string `json:"requestDigest"`
	ExecutionID        string `json:"executionId"`
	SiteVerified       bool   `json:"siteVerified"`
	SiteOwner          bool   `json:"siteOwner"`
	DisposableTestSite bool   `json:"disposableTestSite"`
	WriteClaimed       bool   `json:"writeClaimed"`
	Scope              string `json:"scope"`
	AccessToken        string `json:"accessToken"`
	ExpiresAt          int64  `json:"expiresAt"`
	Acknowledged       bool   `json:"acknowledged"`
	OK                 *bool  `json:"ok"`
}
type authority interface {
	Call(context.Context, string, string, authorityRequest) (credential, error)
}
type cuanAuthority struct {
	Endpoint, ServiceID, ServiceSecret string
	Client                             *http.Client
}

func (a *cuanAuthority) Call(ctx context.Context, key, action string, request authorityRequest) (credential, error) {
	if !connectionKey.MatchString(key) {
		return credential{}, errDenied
	}
	body, _ := canonicalJSON(map[string]any{"action": action, "request": request})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Endpoint, bytes.NewReader(body))
	if err != nil {
		return credential{}, errDenied
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-cuan-search-console-service-id", a.ServiceID)
	req.Header.Set("x-cuan-search-console-service-secret", a.ServiceSecret)
	req.Header.Set("x-cuan-mcp-connection-key", key)
	response, err := a.Client.Do(req)
	if err != nil {
		return credential{}, errDenied
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return credential{}, errDenied
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(raw) > 8192 {
		return credential{}, errDenied
	}
	var value credential
	if json.Unmarshal(raw, &value) != nil || value.OK != nil && !*value.OK {
		return credential{}, errDenied
	}
	return value, nil
}

type googleAPI interface {
	Do(context.Context, string, string, string, any) (map[string]any, error)
}
type googleClient struct {
	Client *http.Client
	Base   string
}

func (g *googleClient) Do(ctx context.Context, token, method, path string, body any) (map[string]any, error) {
	if token == "" || len(token) > 4096 {
		return nil, errDenied
	}
	var data io.Reader
	if body != nil {
		encoded, _ := canonicalJSON(body)
		data = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.Base+path, data)
	if err != nil {
		return nil, errProvider
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, errProvider
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errProvider
	}
	if method == http.MethodPut {
		return map[string]any{}, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, errProvider
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return nil, errProvider
	}
	return value, nil
}

type service struct {
	Authority     authority
	Google        googleAPI
	SigningSecret []byte
	Now           func() time.Time
}

func (s *service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
func (s *service) call(ctx context.Context, key, action string, r authorityRequest, write bool) (credential, error) {
	c, err := s.Authority.Call(ctx, key, action, r)
	if err != nil {
		return credential{}, errDenied
	}
	if c.SiteURL != r.SiteURL || c.RequestDigest != r.RequestDigest || c.ExecutionID != r.ExecutionID || !c.SiteVerified || c.AccessToken == "" || len(c.AccessToken) > 4096 || c.ExpiresAt <= s.now().Add(time.Second).UnixMilli() || !(c.Scope == readScope || c.Scope == writeScope) || write && (c.Scope != writeScope || !c.SiteOwner || !c.DisposableTestSite || !c.WriteClaimed) || r.Operation == "sitemap_preview" && (!c.SiteOwner || !c.DisposableTestSite) {
		return credential{}, errDenied
	}
	return c, nil
}
func (s *service) verifiedSite(ctx context.Context, token, site string, owner bool) error {
	data, err := s.Google.Do(ctx, token, http.MethodGet, "/sites/"+url.PathEscape(site), nil)
	if err != nil {
		return err
	}
	if data["siteUrl"] != site {
		return errDenied
	}
	permission, _ := data["permissionLevel"].(string)
	if owner && permission != "siteOwner" {
		return errDenied
	}
	if !owner && permission != "siteOwner" && permission != "siteFullUser" && permission != "siteRestrictedUser" {
		return errDenied
	}
	return nil
}

type analyticsInput struct {
	SiteURL    string   `json:"site_url"`
	StartDate  string   `json:"start_date"`
	EndDate    string   `json:"end_date"`
	Dimensions []string `json:"dimensions,omitempty"`
	RowLimit   int      `json:"row_limit,omitempty"`
}

func (s *service) analytics(ctx context.Context, key string, in analyticsInput) (any, error) {
	if _, _, _, err := siteIdentity(in.SiteURL); err != nil {
		return nil, err
	}
	start, err := parseDate(in.StartDate)
	if err != nil {
		return nil, err
	}
	end, err := parseDate(in.EndDate)
	if err != nil {
		return nil, err
	}
	if end.Before(start) || end.Sub(start) > 30*24*time.Hour {
		return nil, errInvalid
	}
	dimensions := in.Dimensions
	if dimensions == nil {
		dimensions = []string{"date"}
	}
	if len(dimensions) < 1 || len(dimensions) > 2 {
		return nil, errInvalid
	}
	seen := map[string]bool{}
	for _, d := range dimensions {
		if !allowedDimensions[d] || seen[d] {
			return nil, errInvalid
		}
		seen[d] = true
	}
	limit := in.RowLimit
	if limit == 0 {
		limit = 10
	}
	if limit < 1 || limit > 100 {
		return nil, errInvalid
	}
	executionID, err := newUUID()
	if err != nil {
		return nil, errDenied
	}
	r := authorityRequest{Operation: "search_analytics", SiteURL: in.SiteURL, ExecutionID: executionID, RequestDigest: digest([]any{"search_analytics", in.SiteURL, in.StartDate, in.EndDate, dimensions, limit})}
	c, err := s.call(ctx, key, "resolveRead", r, false)
	if err != nil {
		return nil, err
	}
	if err = s.verifiedSite(ctx, c.AccessToken, in.SiteURL, false); err != nil {
		return nil, err
	}
	data, err := s.Google.Do(ctx, c.AccessToken, http.MethodPost, "/sites/"+url.PathEscape(in.SiteURL)+"/searchAnalytics/query", map[string]any{"startDate": in.StartDate, "endDate": in.EndDate, "dimensions": dimensions, "rowLimit": limit})
	if err != nil {
		return nil, err
	}
	raw, exists := data["rows"]
	if !exists {
		return map[string]any{"siteUrl": in.SiteURL, "rows": []any{}}, nil
	}
	rows, ok := raw.([]any)
	if !ok || len(rows) > limit {
		return nil, errProvider
	}
	out := make([]any, 0, len(rows))
	for _, v := range rows {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, errProvider
		}
		keys, ok := row["keys"].([]any)
		if !ok || len(keys) != len(dimensions) {
			return nil, errProvider
		}
		for _, k := range keys {
			value, ok := k.(string)
			if !ok || len(value) > 512 {
				return nil, errProvider
			}
		}
		for _, name := range []string{"clicks", "impressions", "ctr", "position"} {
			num, ok := row[name].(float64)
			if !ok || num < 0 || num > 1e15 {
				return nil, errProvider
			}
		}
		out = append(out, map[string]any{"keys": keys, "clicks": row["clicks"], "impressions": row["impressions"], "ctr": row["ctr"], "position": row["position"]})
	}
	return map[string]any{"siteUrl": in.SiteURL, "rows": out}, nil
}

type previewInput struct {
	SiteURL    string `json:"site_url"`
	SitemapURL string `json:"sitemap_url"`
}
type previewData struct {
	PreviewID  string `json:"previewId"`
	SiteURL    string `json:"siteUrl"`
	SitemapURL string `json:"sitemapUrl"`
	Digest     string `json:"digest"`
	ExpiresAt  int64  `json:"expiresAt"`
}

func (s *service) sign(p previewData) string {
	b, _ := canonicalJSON(p)
	mac := hmac.New(sha256.New, s.SigningSecret)
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (s *service) verify(token string) (previewData, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(token) > 4096 {
		return previewData{}, errInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return previewData{}, errInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return previewData{}, errInvalid
	}
	mac := hmac.New(sha256.New, s.SigningSecret)
	mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return previewData{}, errDenied
	}
	var p previewData
	if json.Unmarshal(body, &p) != nil || !uuidV4.MatchString(p.PreviewID) || !hexDigest.MatchString(p.Digest) || p.ExpiresAt <= s.now().UnixMilli() || p.ExpiresAt > s.now().Add(previewTTL).UnixMilli() || sitemapTarget(p.SiteURL, p.SitemapURL) != nil || p.Digest != digest([]any{"submit_sitemap", p.SiteURL, p.SitemapURL}) {
		return previewData{}, errDenied
	}
	return p, nil
}
func (s *service) preview(ctx context.Context, key string, in previewInput) (any, error) {
	if err := sitemapTarget(in.SiteURL, in.SitemapURL); err != nil {
		return nil, err
	}
	id, err := newUUID()
	if err != nil {
		return nil, errDenied
	}
	p := previewData{PreviewID: id, SiteURL: in.SiteURL, SitemapURL: in.SitemapURL, Digest: digest([]any{"submit_sitemap", in.SiteURL, in.SitemapURL}), ExpiresAt: s.now().Add(previewTTL).UnixMilli()}
	r := authorityRequest{Operation: "sitemap_preview", SiteURL: in.SiteURL, ExecutionID: id, RequestDigest: p.Digest}
	c, err := s.call(ctx, key, "resolveRead", r, false)
	if err != nil {
		return nil, err
	}
	if err = s.verifiedSite(ctx, c.AccessToken, in.SiteURL, true); err != nil {
		return nil, err
	}
	data, err := s.Google.Do(ctx, c.AccessToken, http.MethodGet, "/sites/"+url.PathEscape(in.SiteURL)+"/sitemaps", nil)
	if err != nil {
		return nil, err
	}
	var submitted bool
	if raw, exists := data["sitemap"]; exists {
		rows, ok := raw.([]any)
		if !ok || len(rows) > 1000 {
			return nil, errProvider
		}
		for _, item := range rows {
			row, ok := item.(map[string]any)
			if ok && row["path"] == in.SitemapURL {
				submitted = true
			}
		}
	}
	return map[string]any{"previewId": id, "siteUrl": in.SiteURL, "sitemapUrl": in.SitemapURL, "digest": p.Digest, "expiresAt": p.ExpiresAt, "previewToken": s.sign(p), "alreadySubmitted": submitted, "requiresConfirmation": true}, nil
}

type submitInput struct {
	PreviewToken string `json:"preview_token"`
	Approved     bool   `json:"approved"`
}

func (s *service) submit(ctx context.Context, key string, in submitInput) (any, error) {
	if !in.Approved {
		return nil, errors.New("CONFIRMATION_REQUIRED")
	}
	p, err := s.verify(in.PreviewToken)
	if err != nil {
		return nil, err
	}
	id, err := newUUID()
	if err != nil {
		return nil, errDenied
	}
	r := authorityRequest{Operation: "submit_sitemap", SiteURL: p.SiteURL, SitemapURL: p.SitemapURL, RequestDigest: p.Digest, ExecutionID: id}
	c, err := s.call(ctx, key, "claimWrite", r, true)
	if err != nil {
		return nil, err
	}
	status := "UNKNOWN_OUTCOME"
	if s.verifiedSite(ctx, c.AccessToken, p.SiteURL, true) == nil {
		base := "/sites/" + url.PathEscape(p.SiteURL) + "/sitemaps"
		if _, e := s.Google.Do(ctx, c.AccessToken, http.MethodPut, base+"/"+url.PathEscape(p.SitemapURL), nil); e == nil {
			list, e1 := s.Google.Do(ctx, c.AccessToken, http.MethodGet, base, nil)
			item, e2 := s.Google.Do(ctx, c.AccessToken, http.MethodGet, base+"/"+url.PathEscape(p.SitemapURL), nil)
			if e1 == nil && e2 == nil && item["path"] == p.SitemapURL {
				if rows, ok := list["sitemap"].([]any); ok && len(rows) <= 1000 {
					for _, v := range rows {
						if row, ok := v.(map[string]any); ok && row["path"] == p.SitemapURL {
							status = "CONFIRMED"
							break
						}
					}
				}
			}
		}
	}
	r.Status = status
	ack, e := s.Authority.Call(ctx, key, "finalizeWrite", r)
	if e != nil || ack.Acknowledged != true {
		return nil, errors.New("FINALIZATION_UNKNOWN")
	}
	return map[string]any{"status": status, "siteUrl": p.SiteURL, "sitemapUrl": p.SitemapURL, "executionId": id}, nil
}
