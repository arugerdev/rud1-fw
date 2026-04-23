package httputil

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMaybeGzip_CompressesWhenAccepted verifies the happy path: an
// Accept-Encoding: gzip request yields a wrapped writer whose output is
// gzip-encoded and decompresses back to the original payload, plus the
// Content-Encoding/Vary headers that let caches key correctly.
func TestMaybeGzip_CompressesWhenAccepted(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")

	w2, closeFn := MaybeGzip(rr, req)
	payload := "hello, gzip world — this is iter 16"
	if _, err := w2.Write([]byte(payload)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("closeFn: %v", err)
	}

	if got := rr.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := rr.Header().Get("Vary"); got != "Accept-Encoding" {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}

	gzr, err := gzip.NewReader(strings.NewReader(rr.Body.String()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gzr.Close()
	plain, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(plain) != payload {
		t.Fatalf("decoded = %q, want %q", string(plain), payload)
	}
}

// TestMaybeGzip_PassThroughWhenNotAccepted locks in the byte-identical
// no-gzip path: no Accept-Encoding header means the wrapper is a no-op and
// the ResponseWriter is returned unchanged. This is the whole backwards-
// compat guarantee.
func TestMaybeGzip_PassThroughWhenNotAccepted(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)

	w2, closeFn := MaybeGzip(rr, req)
	payload := "plaintext body"
	if _, err := w2.Write([]byte(payload)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("closeFn: %v", err)
	}

	if got := rr.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if rr.Body.String() != payload {
		t.Fatalf("body = %q, want %q (verbatim)", rr.Body.String(), payload)
	}
}

// TestMaybeGzip_RespectsExistingEncoding guards against accidental double-
// wrapping: if a middleware has already set Content-Encoding, MaybeGzip must
// return the ResponseWriter unchanged regardless of Accept-Encoding.
func TestMaybeGzip_RespectsExistingEncoding(t *testing.T) {
	rr := httptest.NewRecorder()
	rr.Header().Set("Content-Encoding", "br")

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")

	w2, closeFn := MaybeGzip(rr, req)
	if _, err := w2.Write([]byte("raw bytes")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("closeFn: %v", err)
	}
	if got := rr.Header().Get("Content-Encoding"); got != "br" {
		t.Fatalf("Content-Encoding mutated to %q, want br (preserved)", got)
	}
	if rr.Body.String() != "raw bytes" {
		t.Fatalf("body = %q, want raw bytes", rr.Body.String())
	}
}
