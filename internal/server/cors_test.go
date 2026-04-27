package server

import (
	"net/http/httptest"
	"testing"
)

func TestAllowOriginFunc_ExactAllowList(t *testing.T) {
	fn := allowOriginFunc([]string{"http://localhost:5173", "http://localhost:3000"})
	req := httptest.NewRequest("GET", "http://192.168.1.240:7070/api/foo", nil)

	if !fn(req, "http://localhost:5173") {
		t.Fatal("vite dev origin should be allowed")
	}
	if !fn(req, "http://localhost:3000") {
		t.Fatal("next dev origin should be allowed")
	}
	if fn(req, "http://evil.example.com") {
		t.Fatal("untrusted origin must not be allowed")
	}
}

// The canonical case the panel hits: panel served on port 80 of the
// Pi, API served on port 7070 of the same Pi. The browser tags this
// as cross-origin because the ports differ; we allow it because the
// hostname matches.
func TestAllowOriginFunc_SameHostDifferentPort(t *testing.T) {
	fn := allowOriginFunc(nil)

	req := httptest.NewRequest("GET", "http://192.168.1.240:7070/api/system/info", nil)
	req.Host = "192.168.1.240:7070"

	if !fn(req, "http://192.168.1.240") {
		t.Fatal("same-host port-80 origin should be allowed")
	}
	if !fn(req, "https://192.168.1.240:443") {
		t.Fatal("same-host TLS origin should be allowed")
	}
	// Different host on the LAN — must NOT be allowed even on a private subnet.
	if fn(req, "http://192.168.1.99") {
		t.Fatal("different-host LAN origin must NOT be allowed")
	}
	// Public IP, different host — definitely not.
	if fn(req, "http://203.0.113.5") {
		t.Fatal("public different-host origin must NOT be allowed")
	}
}

// rud1.local mDNS hostname (setup-mode AP path). When the panel is
// reached via mDNS, the Host header is "rud1.local" and the Origin is
// "http://rud1.local" — same hostname, same path, must be allowed.
func TestAllowOriginFunc_MDNSHostname(t *testing.T) {
	fn := allowOriginFunc(nil)
	req := httptest.NewRequest("GET", "http://rud1.local:7070/api/setup/state", nil)
	req.Host = "rud1.local:7070"

	if !fn(req, "http://rud1.local") {
		t.Fatal("rud1.local origin should be allowed when reached via mDNS")
	}
}

// Empty Origin (same-origin navigation) is filtered upstream by the
// cors library; we just ensure our function returns false for it so
// the library's "no Origin → no CORS headers needed" branch runs.
func TestAllowOriginFunc_EmptyOrigin(t *testing.T) {
	fn := allowOriginFunc(nil)
	req := httptest.NewRequest("GET", "http://localhost:7070/api/foo", nil)
	if fn(req, "") {
		t.Fatal("empty origin must not be allowed")
	}
}

// Malformed Origin must not crash and must not be allowed.
func TestAllowOriginFunc_MalformedOrigin(t *testing.T) {
	fn := allowOriginFunc(nil)
	req := httptest.NewRequest("GET", "http://localhost:7070/api/foo", nil)
	if fn(req, "not-a-url") {
		t.Fatal("malformed origin must not be allowed")
	}
}
