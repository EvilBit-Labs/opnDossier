package sanitizer

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
)

func FuzzSanitizeXML(f *testing.F) {
	// Seed corpus with XML containing various sensitive data patterns
	f.Add([]byte(`<config><password>s3cret!</password></config>`))
	f.Add([]byte(`<config><ip>192.168.1.1</ip><ip>10.0.0.1</ip></config>`))
	f.Add([]byte(`<config><email>user@example.com</email></config>`))
	f.Add([]byte(`<config><mac>00:11:22:33:44:55</mac></config>`))
	f.Add([]byte(`<config><host>fw.example.com</host></config>`))
	f.Add([]byte(`<!-- admin password: test123 --><config></config>`))
	f.Add([]byte(`<config><!-- migrated 2024- --></config>`))
	f.Add([]byte(`<config><!-- line one
line two --></config>`))
	f.Add([]byte(`<config attr="192.168.0.1"><value>test</value></config>`))
	f.Add([]byte(`not xml`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		s := NewSanitizer(ModeAggressive)
		var out bytes.Buffer
		// Must not panic; parse errors on malformed XML are expected.
		if err := s.SanitizeXML(bytes.NewReader(data), &out); err != nil {
			return
		}

		// Round-trip invariant: when the sanitizer accepts an input it has
		// re-serialized every token itself, so the result must be a
		// well-formed XML document. A sanitized config that no longer parses
		// is a defect even when every secret was correctly redacted — the
		// output is meant to be loadable/inspectable config.xml, not prose.
		// Strict stays on: this is validating emitted output, not tolerating
		// vendor input. A lenient decoder accepts malformed nesting and unknown
		// entities, which would let the invariant pass on output a downstream
		// strict parser rejects. Raised in review.
		decoder := xml.NewDecoder(bytes.NewReader(out.Bytes()))
		decoder.Entity = map[string]string{}
		for {
			_, err := decoder.Token()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				t.Fatalf("sanitized output is not well-formed XML: %v\ninput:  %q\noutput: %q", err, data, out.String())
			}
		}
	})
}

func FuzzPatternDetection(f *testing.F) {
	// Seed corpus with valid examples of each pattern type
	f.Add("192.168.1.1")
	f.Add("10.0.0.0")
	f.Add("255.255.255.255")
	f.Add("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	f.Add("::1")
	f.Add("fe80::1")
	f.Add("fc00::1")
	f.Add("00:11:22:33:44:55")
	f.Add("AA-BB-CC-DD-EE-FF")
	f.Add("user@example.com")
	f.Add("admin@fw.local")
	f.Add("fw.example.com")
	f.Add("opnsense.localdomain")
	f.Add("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgdGVzdCBzdHJpbmc=")
	f.Add("-----BEGIN CERTIFICATE-----\nMIIBxTCCAW+gAwIBAgIUQ==\n-----END CERTIFICATE-----")
	f.Add("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----")
	f.Add("")
	f.Add("not-a-pattern")
	f.Add("192.168.1.0/24")
	f.Add("fd00::/8")
	f.Add("10.0.0.0/8")
	// Stress test for regex backtracking
	f.Add(strings.Repeat("a", 10000))
	f.Add(strings.Repeat("192.168.1.", 1000))

	f.Fuzz(func(_ *testing.T, s string) {
		// All pattern detection functions must not panic on arbitrary input
		IsIPv4(s)
		IsIP(s)
		IsSubnet(s)
		IsPrivateIP(s)
		IsPublicIP(s)
		IsMAC(s)
		IsEmail(s)
		IsHostname(s)
		IsBase64(s)
		IsPEM(s)
		IsCertificate(s)
		IsPrivateKey(s)
	})
}
