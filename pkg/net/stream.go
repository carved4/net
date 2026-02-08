package net

import (
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"

	wc "github.com/carved4/go-wincall"
)

type StreamConn struct {
	sock      *afdSocket
	tlsClient *TLSClient
	host      string
	closed    bool
	mu        sync.Mutex
}

func DialStream(url string, config *ClientConfig) (*StreamConn, string, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := initSSPI(); err != nil {
		return nil, "", newNetError(ErrSSPIInit, "sspi init", err)
	}
	if err := initCrypt32(); err != nil {
		return nil, "", newNetError(ErrCrypt32Init, "crypt32 init", err)
	}

	host, port, path, err := parseURL(url)
	if err != nil {
		return nil, "", newNetError(ErrHTTPParse, "parse url", err)
	}

	resolver := NewDNSResolver()
	ip, err := resolver.Resolve(host)
	if err != nil {
		return nil, "", newNetError(ErrDNSResolution, "dns resolve", err)
	}

	sock, err := afdCreateTCPSocket()
	if err != nil {
		return nil, "", newNetError(ErrSocketCreate, "socket create", err)
	}

	if err := sock.Bind(); err != nil {
		sock.Close()
		return nil, "", newNetError(ErrSocketBind, "socket bind", err)
	}
	if err := sock.Connect(ip, port); err != nil {
		sock.Close()
		return nil, "", newNetError(ErrConnection, "connect", err)
	}

	tlsClient := new(TLSClient)
	if err := tlsAcquireCredentials(tlsClient); err != nil {
		sock.Close()
		return nil, "", newNetError(ErrTLSHandshake, "tls credentials", err)
	}

	hostW, _ := wc.UTF16ptr(host)
	if config.TLS.ServerName != "" {
		hostW, _ = wc.UTF16ptr(config.TLS.ServerName)
	}

	if config.TLS.SkipVerify {
		if err := tlsHandshakeNoVerify(tlsClient, sock, hostW); err != nil {
			tlsFreeClient(tlsClient)
			sock.Close()
			return nil, "", newNetError(ErrTLSHandshake, "tls handshake", err)
		}
	} else {
		if err := tlsHandshake(tlsClient, sock, hostW); err != nil {
			tlsFreeClient(tlsClient)
			sock.Close()
			return nil, "", newNetError(ErrTLSHandshake, "tls handshake", err)
		}
	}

	return &StreamConn{
		sock:      sock,
		tlsClient: tlsClient,
		host:      host,
	}, path, nil
}

func (c *StreamConn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	tlsFreeClient(c.tlsClient)
	c.sock.Close()
}

func (c *StreamConn) SendChunkedRequest(method, path string, headers map[string]string, bodyReader io.Reader, userAgent string) (*HTTPResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, newNetError(ErrSocketSend, "connection closed", nil)
	}
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteString(" ")
	sb.WriteString(path)
	sb.WriteString(" HTTP/1.1\r\n")
	sb.WriteString("Host: ")
	sb.WriteString(c.host)
	sb.WriteString("\r\n")

	if userAgent != "" {
		sb.WriteString("User-Agent: ")
		sb.WriteString(userAgent)
		sb.WriteString("\r\n")
	}

	sb.WriteString("Transfer-Encoding: chunked\r\n")

	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\r\n")
	}

	sb.WriteString("Connection: close\r\n")
	sb.WriteString("\r\n")

	if err := tlsSend(c.tlsClient, c.sock, []byte(sb.String())); err != nil {
		return nil, newNetError(ErrSocketSend, "send headers", err)
	}

	buf := make([]byte, 8192)
	for {
		n, err := bodyReader.Read(buf)
		if n > 0 {
			chunkHeader := fmt.Sprintf("%x\r\n", n)
			if err := tlsSend(c.tlsClient, c.sock, []byte(chunkHeader)); err != nil {
				return nil, newNetError(ErrSocketSend, "send chunk header", err)
			}

			if err := tlsSend(c.tlsClient, c.sock, buf[:n]); err != nil {
				return nil, newNetError(ErrSocketSend, "send chunk data", err)
			}

			if err := tlsSend(c.tlsClient, c.sock, []byte("\r\n")); err != nil {
				return nil, newNetError(ErrSocketSend, "send chunk footer", err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, newNetError(ErrSocketSend, "read body", err)
		}
	}

	if err := tlsSend(c.tlsClient, c.sock, []byte("0\r\n\r\n")); err != nil {
		return nil, newNetError(ErrSocketSend, "send final chunk", err)
	}

	rawResp, err := tlsRecv(c.tlsClient, c.sock)
	if err != nil && len(rawResp) == 0 {
		return nil, newNetError(ErrSocketRecv, "recv response", err)
	}

	return parseStreamResponse(rawResp)
}

func (c *StreamConn) SendRequest(method, path string, headers map[string]string, body []byte, userAgent string) (*HTTPResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, newNetError(ErrSocketSend, "connection closed", nil)
	}
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteString(" ")
	sb.WriteString(path)
	sb.WriteString(" HTTP/1.1\r\n")
	sb.WriteString("Host: ")
	sb.WriteString(c.host)
	sb.WriteString("\r\n")

	if userAgent != "" {
		sb.WriteString("User-Agent: ")
		sb.WriteString(userAgent)
		sb.WriteString("\r\n")
	}

	if len(body) > 0 {
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}

	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\r\n")
	}

	sb.WriteString("Connection: close\r\n")
	sb.WriteString("\r\n")

	reqData := []byte(sb.String())
	if len(body) > 0 {
		reqData = append(reqData, body...)
	}

	if err := tlsSend(c.tlsClient, c.sock, reqData); err != nil {
		return nil, newNetError(ErrSocketSend, "send request", err)
	}

	rawResp, err := tlsRecv(c.tlsClient, c.sock)
	runtime.KeepAlive(reqData)
	if err != nil && len(rawResp) == 0 {
		return nil, newNetError(ErrSocketRecv, "recv response", err)
	}

	return parseStreamResponse(rawResp)
}

func parseStreamResponse(raw []byte) (*HTTPResponse, error) {
	headerEnd := findHeaderEnd(raw)
	if headerEnd < 0 {
		if len(raw) == 0 {
			return nil, newNetError(ErrHTTPParse, "no data received", nil)
		}
		return &HTTPResponse{RawData: raw, Body: raw}, nil
	}

	headerBytes := raw[:headerEnd]
	statusCode := parseHTTPStatusCode(headerBytes)
	headers := parseHTTPHeaders(headerBytes)
	body := raw[headerEnd+4:]

	var te, ce string
	for k, v := range headers {
		lk := strings.ToLower(k)
		if lk == "transfer-encoding" {
			te = v
		}
		if lk == "content-encoding" {
			ce = v
		}
	}
	body = decodeBody(body, te, ce)

	return &HTTPResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
		RawData:    raw,
	}, nil
}

func PostChunked(url string, headers map[string]string, bodyReader io.Reader, config *Config) (*HTTPResponse, error) {
	cc := toClientConfig(config)
	conn, path, err := DialStream(url, cc)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.SendChunkedRequest("POST", path, headers, bodyReader, cc.HTTP.UserAgent)
}

func PostStream(url string, headers map[string]string, body []byte, config *Config) (*HTTPResponse, error) {
	cc := toClientConfig(config)
	conn, path, err := DialStream(url, cc)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.SendRequest("POST", path, headers, body, cc.HTTP.UserAgent)
}

