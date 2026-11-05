package rdata

import (
	"strings"
	"testing"
)

func TestEqual(t *testing.T) {
	long := strings.Repeat("A", 300)
	cases := []struct {
		typ, a, b string
		want      bool
	}{
		{"A", "192.0.2.1", "192.0.2.1", true},
		{"A", "192.0.2.1", "192.0.2.2", false},
		{"AAAA", "2001:DB8::1", "2001:db8:0:0:0:0:0:1", true},
		{"CNAME", "Target.Example.net", "target.example.net.", true},
		{"CNAME", "target.example.net", "target.example.org.", false},
		{"MX", "10 Mail.example.com", "10 mail.example.com.", true},
		{"MX", "10 mail.example.com.", "20 mail.example.com.", false},
		{"SRV", "10 5 443 Svc.Example.com", "10 5 443 svc.example.com.", true},
		{"NS", "ns-1.awsdns-01.org", "NS-1.AWSDNS-01.ORG.", true},
		{"CAA", `0 issue "letsencrypt.org"`, "0 issue letsencrypt.org", true},
		{"CAA", `0 issue "letsencrypt.org"`, `0 issue "pki.goog"`, false},
		{"TXT", "v=spf1 -all", `"v=spf1 -all"`, true},
		{"TXT", "v=spf1 -all", `"v=spf1" " -all"`, true},
		{"TXT", "v=spf1 -all", `"v=spf1 ~all"`, false},
		{"TXT", "v=DKIM1; k=rsa; p=" + long, `"v=DKIM1; k=rsa; p=` + long[:200] + `" "` + long[200:] + `"`, true},
		{"TXT", `abc""def`, `"abc" "def"`, true},
		{"TXT", `abc""def`, "abcdef", true},
		{"TXT", `say \"hi\"`, `"say \"hi\""`, true},
		{"TXT", "Case", "case", false},
		{"A", "not-an-ip", "not-an-ip", true},
		{"A", "not-an-ip", "Not-an-ip", false},
		{"FOO", "x", "X", false},
		{"TXT", `"unterminated`, `"unterminated"`, false},
	}
	for _, c := range cases {
		if got := Equal(c.typ, c.a, c.b); got != c.want {
			t.Errorf("Equal(%s, %q, %q) = %v, want %v", c.typ, c.a, c.b, got, c.want)
		}
		if got := Equal(c.typ, c.b, c.a); got != c.want {
			t.Errorf("Equal(%s, %q, %q) = %v, want %v (reversed)", c.typ, c.b, c.a, got, c.want)
		}
	}
}

func TestSetEqual(t *testing.T) {
	if !SetEqual("MX", []string{"10 a.example.com", "20 B.example.com."}, []string{"20 b.example.com.", "10 a.example.com."}) {
		t.Fatal("same MX set in another order and form")
	}
	if SetEqual("A", []string{"192.0.2.1", "192.0.2.1"}, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatal("a value matched twice")
	}
	if SetEqual("A", []string{"192.0.2.1"}, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatal("different sizes")
	}
}

func TestNameEqual(t *testing.T) {
	if !NameEqual("d111.cloudfront.net", "D111.CloudFront.net.") || NameEqual("a.example.com", "b.example.com") {
		t.Fatal("NameEqual")
	}
}
