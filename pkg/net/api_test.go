package net

import (
	"strings"
	"testing"
)

func TestGet_ExampleCom(t *testing.T) {
	body, err := Get("https://example.com", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	if !strings.Contains(string(body), "Example Domain") {
		t.Error("body missing expected content")
	}
}

func TestGet_WithPath(t *testing.T) {
	body, err := Get("https://httpbin.org/get", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	if !strings.Contains(string(body), "httpbin") {
		t.Error("body missing expected content")
	}
}

func TestGet_CustomUA(t *testing.T) {
	config := &Config{UserAgent: "TestAgent/1.0"}
	body, err := Get("https://httpbin.org/user-agent", config)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(string(body), "TestAgent/1.0") {
		t.Errorf("expected custom UA in response, got: %s", string(body))
	}
}

func TestGet_CustomHeader(t *testing.T) {
	config := &Config{Headers: map[string]string{"X-Test-Header": "TestValue123"}}
	body, err := Get("https://httpbin.org/headers", config)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(string(body), "TestValue123") {
		t.Errorf("expected custom header in response, got: %s", string(body))
	}
}

func TestPost_HTTPBin(t *testing.T) {
	payload := []byte(`{"test":"value"}`)
	body, err := Post("https://httpbin.org/post", payload, nil)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	if !strings.Contains(string(body), `"test"`) || !strings.Contains(string(body), `"value"`) {
		t.Errorf("expected payload in response, got: %s", string(body))
	}
}

func TestPost_CustomConfig(t *testing.T) {
	payload := []byte(`test=value`)
	config := &Config{
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	body, err := Post("https://httpbin.org/post", payload, config)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if !strings.Contains(string(body), "application/x-www-form-urlencoded") {
		t.Errorf("expected content-type in response, got: %s", string(body))
	}
}

func TestResolve_KnownHost(t *testing.T) {
	ip, err := Resolve("one.one.one.one")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ip == 0 {
		t.Fatal("expected non-zero IP")
	}
	t.Logf("one.one.one.one resolved to %s", IPv4String(ip))
}

func TestResolveAll_Google(t *testing.T) {
	ips, err := ResolveAll("google.com")
	if err != nil {
		t.Fatalf("ResolveAll: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP")
	}
	for _, ip := range ips {
		t.Logf("google.com resolved to %s", IPv4String(ip))
	}
}

func TestIPv4_Parse(t *testing.T) {
	ip := IPv4(192, 168, 1, 1)
	expected := uint32(0x0101a8c0)
	if ip != expected {
		t.Errorf("IPv4(192,168,1,1) = 0x%x, want 0x%x", ip, expected)
	}
}

func TestIPv4String(t *testing.T) {
	ip := IPv4(192, 168, 1, 1)
	s := IPv4String(ip)
	if s != "192.168.1.1" {
		t.Errorf("IPv4String = %q, want 192.168.1.1", s)
	}
}

func TestHTTPClient_Get(t *testing.T) {
	client := NewHTTPClient(nil)
	resp, err := client.Get("https://example.com")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if len(resp.Body) == 0 {
		t.Error("expected non-empty body")
	}
}

func TestHTTPClient_Post(t *testing.T) {
	client := NewHTTPClient(nil)
	resp, err := client.Post("https://httpbin.org/post", []byte("hello"))
	if err != nil {
		t.Fatalf("client.Post: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "hello") {
		t.Error("body missing posted data")
	}
}

func TestHTTPClient_CustomConfig(t *testing.T) {
	config := DefaultConfig().
		WithUserAgent("CustomClient/2.0").
		WithHeader("Accept-Language", "en-US")
	client := NewHTTPClient(config)
	resp, err := client.Get("https://httpbin.org/headers")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	body := string(resp.Body)
	if !strings.Contains(body, "CustomClient/2.0") {
		t.Error("missing custom user agent")
	}
	if !strings.Contains(body, "en-US") {
		t.Error("missing custom header")
	}
}

func TestHTTPClient_Redirect(t *testing.T) {
	client := NewHTTPClient(nil)
	resp, err := client.Get("https://httpbin.org/redirect/2")
	if err != nil {
		t.Fatalf("client.Get redirect: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200 after redirects", resp.StatusCode)
	}
}

func TestHTTPClient_404(t *testing.T) {
	client := NewHTTPClient(nil)
	_, err := client.Get("https://httpbin.org/status/404")
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !IsNetError(err) {
		t.Error("expected NetError")
	}
	if GetNetErrorType(err) != ErrHTTPStatus {
		t.Errorf("expected ErrHTTPStatus, got %v", GetNetErrorType(err))
	}
	if GetNetErrorCode(err) != 404 {
		t.Errorf("expected code 404, got %d", GetNetErrorCode(err))
	}
}

func TestDNSResolver(t *testing.T) {
	resolver := NewDNSResolver()
	ip, err := resolver.Resolve("example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ip == 0 {
		t.Fatal("expected non-zero IP")
	}
	t.Logf("example.com = %s", IPv4String(ip))
}

func TestTLSConn_Dial(t *testing.T) {
	conn, err := Dial("example.com", 443, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	if err := conn.Send(req); err != nil {
		t.Fatalf("Send: %v", err)
	}

	resp, err := conn.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("expected response data")
	}
	if !strings.Contains(string(resp), "HTTP/1.1 200") {
		t.Error("expected HTTP 200 response")
	}
}

func TestRawConn_Dial(t *testing.T) {
	ip, err := Resolve("example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	conn, err := DialRawIP(ip, 80)
	if err != nil {
		t.Fatalf("DialRawIP: %v", err)
	}
	defer conn.Close()

	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	if err := conn.Send(req); err != nil {
		t.Fatalf("Send: %v", err)
	}

	buf := make([]byte, 4096)
	total := 0
	for {
		n, err := conn.Recv(buf[total:])
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if n == 0 {
			break
		}
		total += n
		if total > 100 {
			break
		}
	}
	if total < 12 {
		t.Fatalf("response too short: %d bytes", total)
	}
	if !strings.Contains(string(buf[:total]), "HTTP/1.") {
		t.Error("expected HTTP response")
	}
	t.Logf("received %d bytes via raw TCP", total)
}

func TestConnPool_Basic(t *testing.T) {
	pool := NewConnPool(nil)
	defer pool.Close()

	conn1, err := pool.Get("example.com", 443)
	if err != nil {
		t.Fatalf("pool.Get: %v", err)
	}

	pool.Put(conn1, 443)

	conn2, err := pool.Get("example.com", 443)
	if err != nil {
		t.Fatalf("pool.Get reuse: %v", err)
	}
	conn2.Close()
}

func TestGet_GitHub(t *testing.T) {
	body, err := Get("https://raw.githubusercontent.com/golang/go/master/LICENSE", nil)
	if err != nil {
		t.Fatalf("Get GitHub raw: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	if !strings.Contains(string(body), "BSD") && !strings.Contains(string(body), "Copyright") {
		t.Error("expected license text")
	}
	t.Logf("downloaded %d bytes from GitHub", len(body))
}

func TestGet_GoogleRobots(t *testing.T) {
	body, err := Get("https://www.google.com/robots.txt", nil)
	if err != nil {
		t.Fatalf("Get Google robots.txt: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	if !strings.Contains(string(body), "User-agent") {
		t.Error("expected robots.txt content")
	}
	t.Logf("downloaded %d bytes from Google", len(body))
}

func TestSequentialRequests(t *testing.T) {
	urls := []string{
		"https://example.com",
		"https://httpbin.org/get",
		"https://www.google.com/robots.txt",
	}
	for _, url := range urls {
		body, err := Get(url, nil)
		if err != nil {
			t.Errorf("Get(%s): %v", url, err)
			continue
		}
		if len(body) == 0 {
			t.Errorf("empty body for %s", url)
		}
		t.Logf("[%s] %d bytes", url, len(body))
	}
}

func TestPostWithReader(t *testing.T) {
	data := "hello from reader"
	reader := strings.NewReader(data)
	headers := map[string]string{"Content-Type": "text/plain"}
	body, err := PostWithReader("https://httpbin.org/post", headers, reader, nil)
	if err != nil {
		t.Fatalf("PostWithReader: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	if !strings.Contains(string(body), "hello from reader") {
		t.Errorf("expected data in response, got: %s", string(body))
	}
}

func TestPostWithReader_LargePayload(t *testing.T) {
	data := strings.Repeat("ABCDEFGHIJ", 1000)
	reader := strings.NewReader(data)
	headers := map[string]string{"Content-Type": "application/octet-stream"}
	body, err := PostWithReader("https://httpbin.org/post", headers, reader, nil)
	if err != nil {
		t.Fatalf("PostWithReader large: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	t.Logf("received %d bytes response for large payload", len(body))
}

func TestDownload_NilConfig(t *testing.T) {
	body, err := Download("https://example.com", nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
	if !strings.Contains(string(body), "Example Domain") {
		t.Error("body missing expected content")
	}
}

func TestDownload_WithConfig(t *testing.T) {
	config := &Config{UserAgent: "DownloadTest/1.0"}
	body, err := Download("https://httpbin.org/user-agent", config)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !strings.Contains(string(body), "DownloadTest/1.0") {
		t.Errorf("expected custom UA in response, got: %s", string(body))
	}
}

func TestDialStream_Basic(t *testing.T) {
	conn, path, err := DialStream("https://example.com/testpath", nil)
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer conn.Close()

	if path != "/testpath" {
		t.Errorf("path = %q, want /testpath", path)
	}
}

func TestStreamConn_SendRequest(t *testing.T) {
	conn, path, err := DialStream("https://httpbin.org/get", nil)
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer conn.Close()

	resp, err := conn.SendRequest("GET", path, nil, nil, "StreamTest/1.0")
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "httpbin") {
		t.Error("body missing expected content")
	}
}

func TestStreamConn_SendRequest_WithBody(t *testing.T) {
	conn, path, err := DialStream("https://httpbin.org/post", nil)
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer conn.Close()

	body := []byte(`{"key":"value"}`)
	headers := map[string]string{"Content-Type": "application/json"}
	resp, err := conn.SendRequest("POST", path, headers, body, "StreamTest/1.0")
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "value") {
		t.Errorf("expected body content in response, got: %s", string(resp.Body))
	}
}

func TestStreamConn_SendChunkedRequest(t *testing.T) {
	conn, path, err := DialStream("https://httpbin.org/post", nil)
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer conn.Close()

	reader := strings.NewReader("chunked data payload")
	headers := map[string]string{"Content-Type": "text/plain"}
	resp, err := conn.SendChunkedRequest("POST", path, headers, reader, "StreamTest/1.0")
	if err != nil {
		t.Fatalf("SendChunkedRequest: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "chunked data payload") {
		t.Errorf("expected chunked data in response, got: %s", string(resp.Body))
	}
}

func TestPostChunked(t *testing.T) {
	reader := strings.NewReader("test chunked body")
	headers := map[string]string{"Content-Type": "text/plain"}
	resp, err := PostChunked("https://httpbin.org/post", headers, reader, nil)
	if err != nil {
		t.Fatalf("PostChunked: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "test chunked body") {
		t.Errorf("expected chunked data in response, got: %s", string(resp.Body))
	}
}

func TestPostChunked_WithConfig(t *testing.T) {
	reader := strings.NewReader("configured chunked")
	headers := map[string]string{"Content-Type": "text/plain", "X-Custom": "TestValue"}
	config := &Config{UserAgent: "ChunkedTest/1.0"}
	resp, err := PostChunked("https://httpbin.org/post", headers, reader, config)
	if err != nil {
		t.Fatalf("PostChunked: %v", err)
	}
	if !strings.Contains(string(resp.Body), "ChunkedTest/1.0") {
		t.Errorf("expected custom UA in response, got: %s", string(resp.Body))
	}
	if !strings.Contains(string(resp.Body), "TestValue") {
		t.Errorf("expected custom header in response, got: %s", string(resp.Body))
	}
}

func TestPostStream(t *testing.T) {
	body := []byte("stream post body")
	headers := map[string]string{"Content-Type": "text/plain"}
	resp, err := PostStream("https://httpbin.org/post", headers, body, nil)
	if err != nil {
		t.Fatalf("PostStream: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "stream post body") {
		t.Errorf("expected body in response, got: %s", string(resp.Body))
	}
}

func TestPostStream_WithConfig(t *testing.T) {
	body := []byte("configured stream")
	headers := map[string]string{"Content-Type": "text/plain"}
	config := &Config{UserAgent: "StreamPostTest/1.0"}
	resp, err := PostStream("https://httpbin.org/post", headers, body, config)
	if err != nil {
		t.Fatalf("PostStream: %v", err)
	}
	if !strings.Contains(string(resp.Body), "StreamPostTest/1.0") {
		t.Errorf("expected custom UA in response, got: %s", string(resp.Body))
	}
}

func TestStreamConn_DoubleClose(t *testing.T) {
	conn, _, err := DialStream("https://example.com", nil)
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	conn.Close()
	conn.Close()
}

func TestDialStream_WithCustomHeaders(t *testing.T) {
	conn, path, err := DialStream("https://httpbin.org/headers", nil)
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer conn.Close()

	headers := map[string]string{
		"X-Stream-Test":	"CustomValue",
		"Accept":		"application/json",
	}
	resp, err := conn.SendRequest("GET", path, headers, nil, "HeaderTest/1.0")
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if !strings.Contains(string(resp.Body), "CustomValue") {
		t.Errorf("expected custom header in response, got: %s", string(resp.Body))
	}
}

func TestPostChunked_LargePayload(t *testing.T) {
	data := strings.Repeat("X", 50000)
	reader := strings.NewReader(data)
	headers := map[string]string{"Content-Type": "application/octet-stream"}
	resp, err := PostChunked("https://httpbin.org/post", headers, reader, nil)
	if err != nil {
		t.Fatalf("PostChunked large: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	t.Logf("large chunked upload received %d bytes response", len(resp.Body))
}

