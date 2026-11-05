// Package rdata decides whether two record values (rdata in presentation
// format) mean the same thing, so that the provider does not show a diff
// when the gate returns a value written differently from the configuration.
//
// Each value is parsed with github.com/miekg/dns as the record
// "x.invalid. 300 IN <TYPE> <value>", with "." as origin, and the parsed
// records are compared:
//
//   - domain names inside the rdata (CNAME, NS, PTR, DNAME targets, MX
//     exchanges, SRV targets, SVCB/HTTPS targets...) are absolute: a missing
//     trailing dot is added, and they compare case-insensitively;
//   - every other field compares as parsed (IP addresses in canonical form,
//     numbers as numbers, CAA values with or without quotes);
//   - TXT and SPF values compare on the concatenation of their
//     character-strings: quoting and chunking are ignored, so
//     `v=DKIM1; p=...` (unquoted, any length), `"v=DKIM1; p=..."` and
//     `"v=DKIM1; p=MIIB" "IjANBg..."` are equal. An unquoted value is read as
//     one string, as the AWS provider does: it is wrapped in quotes before
//     parsing, so `a""b` (the aws_route53_record way of splitting a long
//     value) reads as the two strings "a" and "b". Escapes (\" and \DDD)
//     are decoded by the parser on both sides.
//
// A value that does not parse, or a type the parser does not know, compares
// as an exact string. Nothing else is normalized: no reordering inside a
// value, no TTL, no whitespace rules beyond those of the zone file syntax.
package rdata

import (
	"strings"

	"github.com/miekg/dns"
)

const owner = "x.invalid."

// Parse returns the record of a value, nil if it does not parse.
func Parse(typ, value string) dns.RR {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	if _, known := dns.StringToType[typ]; !known || strings.ContainsAny(value, "\n\r;()") && !isText(typ) {
		return nil
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	if isText(typ) && !strings.HasPrefix(v, `"`) {
		v = `"` + value + `"`
	}
	if strings.ContainsAny(v, "\n\r") {
		return nil
	}
	zp := dns.NewZoneParser(strings.NewReader(owner+" 300 IN "+typ+" "+v+"\n"), ".", "")
	rr, ok := zp.Next()
	if !ok || zp.Err() != nil || rr == nil {
		return nil
	}
	if _, more := zp.Next(); more {
		return nil
	}
	return rr
}

func isText(typ string) bool { return typ == "TXT" || typ == "SPF" }

func joined(rr dns.RR) (string, bool) {
	switch r := rr.(type) {
	case *dns.TXT:
		return strings.Join(r.Txt, ""), true
	case *dns.SPF:
		return strings.Join(r.Txt, ""), true
	}
	return "", false
}

// Equal reports whether two values of a record type are the same record.
func Equal(typ, a, b string) bool {
	if a == b {
		return true
	}
	ra, rb := Parse(typ, a), Parse(typ, b)
	if ra == nil || rb == nil {
		return false
	}
	if ja, ok := joined(ra); ok {
		jb, ok := joined(rb)
		return ok && ja == jb
	}
	return dns.IsDuplicate(ra, rb)
}

// SetEqual reports whether two sets of values hold the same records: every
// value of a is equal to a distinct value of b, and conversely.
func SetEqual(typ string, a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
outer:
	for _, x := range a {
		for i, y := range b {
			if !used[i] && Equal(typ, x, y) {
				used[i] = true
				continue outer
			}
		}
		return false
	}
	return true
}

// NameEqual compares two domain names: case-insensitive, trailing dot optional.
func NameEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(a), "."), strings.TrimSuffix(strings.TrimSpace(b), "."))
}
