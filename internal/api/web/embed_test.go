package web

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIndexHTML_NotEmpty(t *testing.T) {
	body, ct := IndexHTML()
	if len(body) == 0 {
		t.Fatal("IndexHTML returned empty body")
	}
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html content type, got %q", ct)
	}
	if !bytes.Contains(body, []byte("<!doctype html>")) {
		t.Errorf("expected HTML doctype in body, got first 80 bytes: %q",
			string(body[:min(80, len(body))]))
	}
}

func TestHandler_ServesIndexAtRoot(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if !bytes.Contains(body, []byte("<!doctype html>")) {
		t.Errorf("expected HTML body, got first 80 bytes: %q",
			string(body[:min(80, len(body))]))
	}
}

func TestHandler_404OnMissingAsset(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/assets/does-not-exist.js", http.NoBody)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing asset, got %d", rec.Code)
	}
}

func TestHandler_FallsBackToIndexForUnknownRoute(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/some/spa/route", http.NoBody)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
