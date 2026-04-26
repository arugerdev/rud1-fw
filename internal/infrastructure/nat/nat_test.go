package nat

import "testing"

func TestIsReachable(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"not a valid endpoint", false},
		{"127.0.0.1:51820", false},     // loopback
		{"0.0.0.0:51820", false},       // unspecified
		{"169.254.1.1:51820", false},   // link-local
		{"10.0.0.5:51820", false},      // RFC1918 private
		{"192.168.1.1:51820", false},   // RFC1918 private
		{"172.16.0.1:51820", false},    // RFC1918 private
		{"203.0.113.5:51820", true},    // TEST-NET-3, public-shaped
		{"8.8.8.8:51820", true},        // public
		{"100.64.0.1:51820", true},     // CGNAT — Reachable does not gate
		{"8.8.8.8", false},             // missing port
		{"8.8.8.8:0", false},           // invalid port
		{"8.8.8.8:99999", false},       // invalid port
	}
	for _, tc := range cases {
		if got := IsReachable(tc.in); got != tc.want {
			t.Errorf("IsReachable(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIsCGNATEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"100.64.0.1:51820", true},   // CGNAT range start
		{"100.127.255.254:51820", true},
		{"100.63.255.255:51820", false}, // just below CGNAT
		{"100.128.0.0:51820", false},    // just above CGNAT
		{"203.0.113.5:51820", false},    // public
		{"127.0.0.1:51820", false},      // loopback
		{"100.64.0.1", true},            // bare IP, no port
		{"::1", false},                  // IPv6 loopback
		{"2606:4700:4700::1111:51820", false}, // IPv6 ignored
		{"not-an-ip:51820", false},
	}
	for _, tc := range cases {
		if got := IsCGNATEndpoint(tc.in); got != tc.want {
			t.Errorf("IsCGNATEndpoint(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
