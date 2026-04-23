// Package httputil hosts tiny HTTP response helpers shared across handlers.
//
// The helpers are intentionally kept dependency-free (stdlib only) so any
// handler package can pull them in without circular-import gymnastics.
package httputil

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

// gzipResponseWriter wraps an http.ResponseWriter so Write() calls are piped
// through a gzip.Writer. We deliberately keep the type unexported — callers
// get a plain io.Writer + a Close function back from MaybeGzip, which is
// enough to drop-in replace the original http.ResponseWriter for body writes.
//
// We do NOT satisfy http.ResponseWriter on purpose: our two export handlers
// call Header() / WriteHeader() BEFORE wrapping (per the helper's contract),
// so they only need an io.Writer for the streamed body. Keeping the surface
// small prevents callers from accidentally writing headers to the wrapper
// after gzip framing has begun.
type gzipResponseWriter struct {
	gz *gzip.Writer
}

// Write forwards bytes into the gzip stream. The underlying ResponseWriter
// receives only the compressed output.
func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	return g.gz.Write(p)
}

// closeFunc is the tiny cleanup closure returned by MaybeGzip. Callers must
// `defer` it; when gzip was engaged it flushes+closes the gzip.Writer so the
// trailer bytes make it to the wire. When gzip was not engaged it is a no-op.
type closeFunc func() error

// MaybeGzip transparently wraps w in a gzip layer when the client advertises
// support via Accept-Encoding. The contract:
//
//   - If r.Header["Accept-Encoding"] contains "gzip" (simple substring match;
//     full q-value parsing would be overkill for an internal admin API) AND
//     the response has not already set Content-Encoding, the returned
//     io.Writer compresses everything written to it and the returned
//     closeFunc flushes+closes the gzip.Writer. Content-Encoding: gzip and
//     Vary: Accept-Encoding are added automatically.
//   - Otherwise, the original w is returned unchanged (no wrapper allocation)
//     and closeFunc is a no-op. This makes the no-gzip path byte-identical
//     to the pre-helper behaviour, which is the whole point of the transparent
//     knob.
//
// Callers MUST set Content-Type / Content-Disposition BEFORE invoking
// MaybeGzip — gzip framing begins as soon as the first body byte is written,
// and late header mutations after that point are silently dropped by
// net/http. Callers MUST NOT set Content-Length: the compressed size is
// unknown up-front and we deliberately stream.
//
// The returned closeFunc MUST be deferred. Forgetting it will produce a
// truncated gzip stream (missing CRC32 + ISIZE trailer) that most decoders
// flag as corrupt.
func MaybeGzip(w http.ResponseWriter, r *http.Request) (io.Writer, closeFunc) {
	// Already encoded — respect the caller's choice and bail out. This guards
	// against accidental double-wrapping if a future middleware also gzips.
	if w.Header().Get("Content-Encoding") != "" {
		return w, func() error { return nil }
	}
	// Simple substring match: handlers we target are admin-scoped and every
	// realistic client (curl, browser, rud1-web) sends either "gzip" or
	// "gzip, deflate". Full RFC 7231 parsing (q=0 suppression, "identity"
	// negotiation) would be ceremony with no payoff here.
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return w, func() error { return nil }
	}

	// Vary is set unconditionally on the gzip branch so intermediary caches
	// know the payload varies on Accept-Encoding. Doing it only here — rather
	// than on both branches — keeps the no-gzip path byte-identical to the
	// pre-helper behaviour.
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Vary", "Accept-Encoding")
	// Any upstream Content-Length would be for the uncompressed payload and
	// thus wrong; defensively strip it. Our two export handlers don't set it
	// today, but a future caller might.
	w.Header().Del("Content-Length")

	gz := gzip.NewWriter(w)
	wrapper := &gzipResponseWriter{gz: gz}
	return wrapper, func() error {
		// Close flushes any pending data and writes the gzip trailer.
		return gz.Close()
	}
}
