package net

import (
	"strings"
	"testing"
)

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

func TestAfdConnect(t *testing.T) {
	sock, err := afdCreateTCPSocket()
	if err != nil {
		t.Fatalf("afdCreateTCPSocket: %v", err)
	}
	defer sock.Close()

	if err := sock.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	ip := htonl(0x01010101)
	if err := sock.Connect(ip, 443); err != nil {
		t.Fatalf("Connect to 1.1.1.1:443: %v", err)
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

	ip := htonl(0x7F000001)
	err = sock.Connect(ip, 1)
	if err == nil {
		t.Fatal("expected connection error to 127.0.0.1:1")
	}
}

func TestAfdSendRecv_HTTP(t *testing.T) {
	sock, err := afdCreateTCPSocket()
	if err != nil {
		t.Fatalf("afdCreateTCPSocket: %v", err)
	}
	defer sock.Close()

	if err := sock.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	ip, err := dnsResolve("example.com")
	if err != nil {
		t.Fatalf("dnsResolve: %v", err)
	}

	if err := sock.Connect(ip, 80); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	if err := sock.Send(req); err != nil {
		t.Fatalf("Send: %v", err)
	}

	resp := make([]byte, 4096)
	n, err := sock.Recv(resp)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if n == 0 {
		t.Fatal("no response received")
	}

	respStr := string(resp[:n])
	if len(respStr) < 12 {
		t.Fatalf("response too short: %d bytes", n)
	}
	if respStr[:4] != "HTTP" {
		t.Errorf("expected HTTP response, got: %s", respStr[:min(50, len(respStr))])
	}
}

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

func TestDownloadToMemory_SmallPage(t *testing.T) {

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

func TestHttpsGet_ExampleCom(t *testing.T) {
	rawResp, err := httpsGet("example.com", 443, "/")
	if err != nil {
		t.Fatalf("httpsGet: %v", err)
	}
	if len(rawResp) == 0 {
		t.Fatal("expected non-empty response")
	}

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
	rawResp, err := httpsGet("httpbin.org", 443, "/status/404")
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

