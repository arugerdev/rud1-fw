// Package middleware provides Chi-compatible HTTP middleware for the local API server.
package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// RequestLogger returns a zerolog-based middleware that logs every request.
func RequestLogger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)
			log.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", ww.status).
				Dur("duration", time.Since(start)).
				Str("remote", r.RemoteAddr).
				Msg("http")
		})
	}
}

// BearerAuth returns a middleware that validates the Authorization: Bearer header.
// If expectedToken is empty, authentication is skipped entirely (no-auth mode).
func BearerAuth(expectedToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if expectedToken == "" {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == "" || token == authHeader {
				writeJSONError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
				return
			}
			if token != expectedToken {
				writeJSONError(w, http.StatusForbidden, "invalid token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Recovery returns a middleware that catches panics and writes a 500 JSON response.
func Recovery() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error().Interface("panic", rec).Str("path", r.URL.Path).Msg("recovered from panic")
					writeJSONError(w, http.StatusInternalServerError, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
