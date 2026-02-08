package net

import (
	"encoding/binary"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// AFD socket creation + close
// ---------------------------------------------------------------------------

func TestAfdCreateTCPSocket(t *testing.T) {
	sock, err := afdCreateTCPSocket()
	if err != nil {
		t.Fatalf("afdCreateTCPSocket: %v", err)
	}
	if sock == nil || sock.handle == 0 {
		t.Fatal("expected valid socket handle")
	}
	sock.Close()
	if sock.handle != 0 {
		t.Error("handle should be zeroed after Close")
	}
}

func TestAfdSocketDoubleClose(t *testing.T) {
	sock, err := afdCreateTCPSocket()
	if err != nil {
		t.Fatalf("afdCreateTCPSocket: %v", err)
	}
	sock.Close()
	// second close should be a no-op, not panic
	sock.Close()
	if sock.handle != 0 {
		t.Error("handle should remain zero after double close")
	}
}

func TestAfdCreateMultipleSockets(t *testing.T) {
	const n = 5
	socks := make([]*afdSocket, n)
	for i := range socks {
		s, err := afdCreateTCPSocket()
		if err != nil {
			t.Fatalf("socket %d: %v", i, err)
		}
		socks[i] = s
	}
	// all handles should be distinct
	seen := map[uintptr]bool{}
	for i, s := range socks {
		if seen[s.handle] {
			t.Errorf("socket %d has duplicate handle 0x%x", i, s.handle)
		}
		seen[s.handle] = true
	}
	for _, s := range socks {
		s.Close()
	}
}

// ---------------------------------------------------------------------------
// Bind
// ---------------------------------------------------------------------------

func TestAfdBind(t *testing.T) {
	sock, err := afdCreateTCPSocket()
	if err != nil {
		t.Fatalf("afdCreateTCPSocket: %v", err)
	}
	defer sock.Close()

	if err := sock.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Connect to a known TCP service (1.1.1.1:53 — Cloudflare DNS over TCP)
// ---------------------------------------------------------------------------

func TestAfdConnect(t *testing.T) {
	sock, err := afdCreateTCPSocket()
	if err != nil {
		t.Fatalf("afdCreateTCPSocket: %v", err)
	}
	defer sock.Close()

	if err := sock.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	// 1.1.1.1 in network byte order
	ip := htonl(0x01010101)
	if err := sock.Connect(ip, 53); err != nil {
		t.Fatalf("Connect to 1.1.1.1:53: %v", err)
	}
}

func TestAfdConnectRefused(t *testing.T) {
	sock, err := afdCreateTCPSocket()
	if err != nil {
		t.Fatalf("afdCreateTCPSocket: %v", err)
	}
	defer sock.Close()

	if err := sock.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	// 127.0.0.1 port 1 — almost certainly refused
	ip := htonl(0x7F000001)
	err = sock.Connect(ip, 1)
	if err == nil {
		t.Fatal("expected connection error to 127.0.0.1:1")
	}
}

// ---------------------------------------------------------------------------
// Send + Recv: do a raw DNS query over TCP to 1.1.1.1
// ---------------------------------------------------------------------------

func TestAfdSendRecv_DNSQuery(t *testing.T) {
	sock, err := afdCreateTCPSocket()
	if err != nil {
		t.Fatalf("afdCreateTCPSocket: %v", err)
	}
	defer sock.Close()

	if err := sock.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := sock.Connect(htonl(0x01010101), 53); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Build a DNS query for "example.com" A record
	txID := uint16(0x1234)
	var msg []byte
	msg = binary.BigEndian.AppendUint16(msg, txID)
	msg = binary.BigEndian.AppendUint16(msg, 0x0100) // standard query, RD=1
	msg = binary.BigEndian.AppendUint16(msg, 1)      // QDCOUNT
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	// QNAME: example.com
	msg = append(msg, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	msg = binary.BigEndian.AppendUint16(msg, 1) // QTYPE A
	msg = binary.BigEndian.AppendUint16(msg, 1) // QCLASS IN

	// TCP DNS: 2-byte length prefix
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if err := sock.Send(lenBuf[:]); err != nil {
		t.Fatalf("Send length: %v", err)
	}
	if err := sock.Send(msg); err != nil {
		t.Fatalf("Send msg: %v", err)
	}

	// Read 2-byte response length
	var respLenBuf [2]byte
	n, err := sock.Recv(respLenBuf[:])
	if err != nil {
		t.Fatalf("Recv length: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 bytes for length, got %d", n)
	}
	respLen := int(binary.BigEndian.Uint16(respLenBuf[:]))
	if respLen < 12 {
		t.Fatalf("response too short: %d", respLen)
	}

	// Read full response
	resp := make([]byte, respLen)
	total := 0
	for total < respLen {
		n, err := sock.Recv(resp[total:])
		if err != nil {
			t.Fatalf("Recv body: %v", err)
		}
		if n == 0 {
			t.Fatal("connection closed before full response")
		}
		total += n
	}

	// Verify we got a valid response
	respID := binary.BigEndian.Uint16(resp[0:2])
	if respID != txID {
		t.Errorf("txID mismatch: got 0x%04X, want 0x%04X", respID, txID)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		t.Error("QR bit not set in response")
	}
	anCount := binary.BigEndian.Uint16(resp[6:8])
	if anCount == 0 {
		t.Error("expected at least one answer record")
	}
}

// ---------------------------------------------------------------------------
// dnsResolve — full DNS resolution through AFD
// ---------------------------------------------------------------------------

func TestDnsResolve_KnownHost(t *testing.T) {
	ip, err := dnsResolve("one.one.one.one")
	if err != nil {
		t.Fatalf("dnsResolve: %v", err)
	}
	if ip == 0 {
		t.Fatal("expected non-zero IP")
	}
}

func TestDnsResolve_InvalidLabel(t *testing.T) {
	_, err := dnsResolve("example..com")
	if err == nil {
		t.Fatal("expected error for empty label")
	}
}

func TestDnsResolve_GoogleDNS(t *testing.T) {
	ip, err := dnsResolve("dns.google")
	if err != nil {
		t.Fatalf("dnsResolve(dns.google): %v", err)
	}
	if ip == 0 {
		t.Fatal("expected non-zero IP for dns.google")
	}
}

// ---------------------------------------------------------------------------
// Full HTTPS download via DownloadToMemory
// ---------------------------------------------------------------------------

func TestDownloadToMemory_SmallPage(t *testing.T) {
	// example.com is a stable, small page served over HTTPS
	body, err := DownloadToMemory("https://example.com")
	if err != nil {
		t.Fatalf("DownloadToMemory(example.com): %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	t.Logf("first 200 chars: %s", string(body[:min(len(body), 200)]))
	if !strings.Contains(string(body), "Example Domain") {
		t.Error("body does not contain expected 'Example Domain' text")
	}
}

func TestDownloadToMemory_WithPath(t *testing.T) {
	// httpbin.org returns JSON; just verify we get data back
	body, err := DownloadToMemory("https://httpbin.org/get")
	if err != nil {
		t.Fatalf("DownloadToMemory(httpbin.org/get): %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	t.Logf("first 200 chars: %s", string(body[:min(len(body), 200)]))
	if !strings.Contains(string(body), "httpbin") {
		t.Errorf("unexpected body content: %s", string(body[:min(len(body), 200)]))
	}
}

func TestDownloadToMemory_Redirect(t *testing.T) {
	// http://www.example.com typically redirects — but we only support https
	// Use a known HTTPS redirect: github.com -> somewhere
	// Instead, test with a URL that we know returns 200 after potential redirects
	body, err := DownloadToMemory("https://www.example.com")
	if err != nil {
		t.Fatalf("DownloadToMemory(www.example.com): %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	t.Logf("first 200 chars: %s", string(body[:min(len(body), 200)]))
}

func TestDownloadToMemory_InvalidScheme(t *testing.T) {
	_, err := DownloadToMemory("http://example.com")
	if err == nil {
		t.Fatal("expected error for http:// scheme")
	}
}

func TestDownloadToMemory_BadHost(t *testing.T) {
	_, err := DownloadToMemory("https://this-domain-definitely-does-not-exist-abc123xyz.com")
	if err == nil {
		t.Fatal("expected DNS resolution error for non-existent domain")
	}
}

func TestDownloadToMemory_EmptyURL(t *testing.T) {
	_, err := DownloadToMemory("")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

// ---------------------------------------------------------------------------
// httpsGet directly
// ---------------------------------------------------------------------------

func TestHttpsGet_ExampleCom(t *testing.T) {
	rawResp, err := httpsGet("example.com", "/")
	if err != nil {
		t.Fatalf("httpsGet: %v", err)
	}
	if len(rawResp) == 0 {
		t.Fatal("expected non-empty response")
	}
	// Should contain HTTP headers
	s := string(rawResp)
	if !strings.Contains(s, "HTTP/1.") {
		t.Error("response missing HTTP status line")
	}
	t.Logf("first 300 chars: %s", s[:min(len(s), 300)])
	if !strings.Contains(s, "Example Domain") {
		t.Error("response missing expected body content")
	}
}

func TestHttpsGet_404(t *testing.T) {
	rawResp, err := httpsGet("httpbin.org", "/status/404")
	if err != nil {
		t.Fatalf("httpsGet: %v", err)
	}
	headerEnd := findHeaderEnd(rawResp)
	if headerEnd < 0 {
		t.Fatal("could not find header end")
	}
	code := parseHTTPStatusCode(rawResp[:headerEnd])
	if code != 404 {
		t.Errorf("expected status 404, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// Stress: multiple sequential downloads
// ---------------------------------------------------------------------------

func TestDownloadToMemory_Sequential(t *testing.T) {
	urls := []string{
		"https://example.com",
		"https://example.com",
		"https://example.com",
	}
	for _, u := range urls {
		body, err := DownloadToMemory(u)
		if err != nil {
			t.Fatalf("DownloadToMemory(%s): %v", u, err)
		}
		if len(body) == 0 {
			t.Errorf("empty body for %s", u)
		}
		t.Logf("[%s] first 100 chars: %s", u, string(body[:min(len(body), 100)]))
	}
}

// ---------------------------------------------------------------------------
// helper: min (for Go < 1.21 compat)
// ---------------------------------------------------------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
