// Package handlers contains the HTTP handler implementations for the local API.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rud1-es/rud1-fw/internal/server/httputil"
)

// writeJSON serialises v as JSON and writes it with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONMaybeGzip mirrors writeJSON but transparently gzips the body when
// the request advertises support. Use for payloads that can grow to several
// kilobytes (lists/ring-buffer dumps) where the gzip savings pay for the
// extra CPU. For small/fixed-size responses keep writeJSON — the compressed
// output often exceeds the uncompressed payload below ~200 bytes.
func writeJSONMaybeGzip(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	bodyW, closeFn := httputil.MaybeGzip(w, r)
	defer func() { _ = closeFn() }()
	_ = json.NewEncoder(bodyW).Encode(v)
}

// writeError writes a JSON error body with the given status code.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
