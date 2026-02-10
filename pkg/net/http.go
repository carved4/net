package net

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	wc "github.com/carved4/go-wincall"
)

type HTTPMethod int

const (
	MethodGET	HTTPMethod	= iota
	MethodPOST
	MethodPUT
	MethodDELETE
	MethodHEAD
	MethodPATCH
)

func (m HTTPMethod) String() string {
	switch m {
	case MethodGET:
		return "GET"
	case MethodPOST:
		return "POST"
	case MethodPUT:
		return "PUT"
	case MethodDELETE:
		return "DELETE"
	case MethodHEAD:
		return "HEAD"
	case MethodPATCH:
		return "PATCH"
	}
	return "GET"
}

type HTTPRequest struct {
	Method	HTTPMethod
	URL	string
	Host	string
	Port	uint16
	Path	string
	Headers	map[string]string
	Body	[]byte
}

type HTTPResponse struct {
	StatusCode	int
	Headers		map[string]string
	Body		[]byte
	RawData		[]byte
}

type HTTPClient struct {
	config		*ClientConfig
	resolver	*DNSResolver
}

func NewHTTPClient(config *ClientConfig) *HTTPClient {
	if config == nil {
		config = DefaultConfig()
	}
	return &HTTPClient{
		config:		config,
		resolver:	NewDNSResolver(),
	}
}

func (c *HTTPClient) Get(url string) (*HTTPResponse, error) {
	return c.Do(&HTTPRequest{Method: MethodGET, URL: url})
}

func (c *HTTPClient) Post(url string, body []byte) (*HTTPResponse, error) {
	return c.Do(&HTTPRequest{Method: MethodPOST, URL: url, Body: body})
}

func (c *HTTPClient) PostWithHeaders(url string, body []byte, headers map[string]string) (*HTTPResponse, error) {
	return c.Do(&HTTPRequest{Method: MethodPOST, URL: url, Body: body, Headers: headers})
}

func (c *HTTPClient) Do(req *HTTPRequest) (*HTTPResponse, error) {
	if err := initSSPI(); err != nil {
		return nil, newNetError(ErrSSPIInit, "sspi init", err)
	}
	if err := initCrypt32(); err != nil {
		return nil, newNetError(ErrCrypt32Init, "crypt32 init", err)
	}

	currentURL := req.URL
	for attempt := 0; attempt <= c.config.HTTP.MaxRedirects; attempt++ {
		host, port, path, err := parseURL(currentURL)
		if err != nil {
			return nil, newNetError(ErrHTTPParse, "parse url", err)
		}
		req.Host = host
		req.Port = port
		req.Path = path

		resp, redirectURL, err := c.doRequest(req)
		if err != nil {
			return nil, err
		}
		if redirectURL != "" {
			if strings.HasPrefix(redirectURL, "/") {
				if port != 443 {
					redirectURL = fmt.Sprintf("https://%s:%d%s", host, port, redirectURL)
				} else {
					redirectURL = "https://" + host + redirectURL
				}
			}
			currentURL = redirectURL
			continue
		}
		return resp, nil
	}
	return nil, newNetError(ErrHTTPRedirect, "too many redirects", nil)
}

func (c *HTTPClient) doRequest(req *HTTPRequest) (*HTTPResponse, string, error) {
	ip, err := c.resolver.Resolve(req.Host)
	if err != nil {
		return nil, "", newNetError(ErrDNSResolution, "dns resolve", err)
	}

	sock, err := afdCreateTCPSocket()
	if err != nil {
		return nil, "", newNetError(ErrSocketCreate, "socket create", err)
	}
	defer sock.Close()

	if err := sock.Bind(); err != nil {
		return nil, "", newNetError(ErrSocketBind, "socket bind", err)
	}
	if err := sock.Connect(ip, req.Port); err != nil {
		return nil, "", newNetError(ErrConnection, "connect", err)
	}

	var tlsClient TLSClient
	defer tlsFreeClient(&tlsClient)

	if err := tlsAcquireCredentials(&tlsClient); err != nil {
		return nil, "", newNetError(ErrTLSHandshake, "tls credentials", err)
	}

	hostW, _ := wc.UTF16ptr(req.Host)
	if c.config.TLS.ServerName != "" {
		hostW, _ = wc.UTF16ptr(c.config.TLS.ServerName)
	}

	if c.config.TLS.SkipVerify {
		if err := tlsHandshakeNoVerify(&tlsClient, sock, hostW); err != nil {
			return nil, "", newNetError(ErrTLSHandshake, "tls handshake", err)
		}
	} else {
		if err := tlsHandshake(&tlsClient, sock, hostW); err != nil {
			return nil, "", newNetError(ErrTLSHandshake, "tls handshake", err)
		}
	}

	httpReq := c.buildHTTPRequest(req)
	if err := tlsSend(&tlsClient, sock, httpReq); err != nil {
		return nil, "", newNetError(ErrSocketSend, "tls send", err)
	}

	rawResp, err := tlsRecv(&tlsClient, sock)
	runtime.KeepAlive(hostW)
	runtime.KeepAlive(httpReq)
	if err != nil && len(rawResp) == 0 {
		return nil, "", newNetError(ErrSocketRecv, "tls recv", err)
	}

	return c.parseResponse(rawResp, req.Host)
}

func (c *HTTPClient) buildHTTPRequest(req *HTTPRequest) []byte {
	var sb strings.Builder
	sb.WriteString(req.Method.String())
	sb.WriteString(" ")
	sb.WriteString(req.Path)
	sb.WriteString(" HTTP/1.1\r\n")
	sb.WriteString("Host: ")
	sb.WriteString(req.Host)
	sb.WriteString("\r\n")

	hasUA := false
	hasAccept := false
	hasConnection := false
	hasContentLength := false
	hasContentType := false

	for k, v := range c.config.HTTP.Headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\r\n")
		lk := strings.ToLower(k)
		if lk == "user-agent" {
			hasUA = true
		}
		if lk == "accept" {
			hasAccept = true
		}
		if lk == "connection" {
			hasConnection = true
		}
		if lk == "content-length" {
			hasContentLength = true
		}
		if lk == "content-type" {
			hasContentType = true
		}
	}

	for k, v := range req.Headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\r\n")
		lk := strings.ToLower(k)
		if lk == "user-agent" {
			hasUA = true
		}
		if lk == "accept" {
			hasAccept = true
		}
		if lk == "connection" {
			hasConnection = true
		}
		if lk == "content-length" {
			hasContentLength = true
		}
		if lk == "content-type" {
			hasContentType = true
		}
	}

	if !hasUA && c.config.HTTP.UserAgent != "" {
		sb.WriteString("User-Agent: ")
		sb.WriteString(c.config.HTTP.UserAgent)
		sb.WriteString("\r\n")
	}

	if !hasAccept {
		sb.WriteString("Accept: */*\r\n")
	}

	hasAcceptEncoding := false
	for k := range c.config.HTTP.Headers {
		if strings.ToLower(k) == "accept-encoding" {
			hasAcceptEncoding = true
			break
		}
	}
	for k := range req.Headers {
		if strings.ToLower(k) == "accept-encoding" {
			hasAcceptEncoding = true
			break
		}
	}
	if !hasAcceptEncoding {
		sb.WriteString("Accept-Encoding: gzip, deflate\r\n")
	}

	if !hasConnection {
		if c.config.HTTP.KeepAlive {
			sb.WriteString("Connection: keep-alive\r\n")
		} else {
			sb.WriteString("Connection: close\r\n")
		}
	}

	if len(req.Body) > 0 {
		if !hasContentLength {
			sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(req.Body)))
		}
		if !hasContentType {
			sb.WriteString("Content-Type: application/octet-stream\r\n")
		}
	}

	sb.WriteString("\r\n")
	result := []byte(sb.String())
	if len(req.Body) > 0 {
		result = append(result, req.Body...)
	}
	return result
}

func (c *HTTPClient) parseResponse(raw []byte, host string) (*HTTPResponse, string, error) {
	headerEnd := findHeaderEnd(raw)
	if headerEnd < 0 {
		if len(raw) == 0 {
			return nil, "", newNetError(ErrHTTPParse, "no data received", nil)
		}
		return &HTTPResponse{RawData: raw, Body: raw}, "", nil
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

	resp := &HTTPResponse{
		StatusCode:	statusCode,
		Headers:	headers,
		Body:		body,
		RawData:	raw,
	}

	if statusCode >= 301 && statusCode <= 308 {
		location := parseLocationHeader(headerBytes)
		if location == "" {
			return nil, "", newNetErrorCode(ErrHTTPRedirect, fmt.Sprintf("HTTP %d redirect with no Location", statusCode), statusCode)
		}
		return resp, location, nil
	}

	if statusCode < 200 || statusCode >= 300 {
		return resp, "", newNetErrorCode(ErrHTTPStatus, fmt.Sprintf("HTTP %d", statusCode), statusCode)
	}

	return resp, "", nil
}

func parseHTTPHeaders(header []byte) map[string]string {
	headers := make(map[string]string)
	lines := strings.Split(string(header), "\r\n")
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		idx := strings.IndexByte(line, ':')
		if idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}
	return headers
}

func tlsHandshakeNoVerify(client *TLSClient, sock *afdSocket, hostW *uint16) error {
	const bufSize = 16384
	contextReq := uintptr(ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
		ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM)

	data := make([]byte, bufSize)
	dataLen := uint32(0)

	for {
		inBufs := new([2]SecBuffer)
		inBufs[0] = SecBuffer{CbBuffer: dataLen, BufferType: SECBUFFER_TOKEN}
		if dataLen > 0 {
			inBufs[0].PvBuffer = uintptr(unsafePointer(&data[0]))
		}
		inBufs[1] = SecBuffer{BufferType: SECBUFFER_EMPTY}
		inDesc := &SecBufferDesc{UlVersion: SECBUFFER_VERSION, CBuffers: 2, PBuffers: &inBufs[0]}

		outBuf := new(SecBuffer)
		outBuf.BufferType = SECBUFFER_TOKEN
		outDesc := &SecBufferDesc{UlVersion: SECBUFFER_VERSION, CBuffers: 1, PBuffers: outBuf}

		attrs := new(uint32)
		expiry := new(SECURITY_INTEGER)
		var status uintptr

		if !client.ContextInitialized {
			status, _, _ = wc.CallG0(sspiTable.InitializeSecurityContextW,
				uintptr(unsafePointer(&client.CredentialHandle)),
				0,
				uintptr(unsafePointer(hostW)),
				contextReq, 0,
				uintptr(SECURITY_NATIVE_DREP),
				0, 0,
				uintptr(unsafePointer(&client.ContextHandle)),
				uintptr(unsafePointer(outDesc)),
				uintptr(unsafePointer(attrs)),
				uintptr(unsafePointer(expiry)))
			client.ContextInitialized = true
		} else {
			status, _, _ = wc.CallG0(sspiTable.InitializeSecurityContextW,
				uintptr(unsafePointer(&client.CredentialHandle)),
				uintptr(unsafePointer(&client.ContextHandle)),
				uintptr(unsafePointer(hostW)),
				contextReq, 0,
				uintptr(SECURITY_NATIVE_DREP),
				uintptr(unsafePointer(inDesc)),
				0, 0,
				uintptr(unsafePointer(outDesc)),
				uintptr(unsafePointer(attrs)),
				uintptr(unsafePointer(expiry)))
		}

		if outBuf.PvBuffer != 0 && outBuf.CbBuffer > 0 {
			outSlice := unsafeSlice((*byte)(unsafePointerFromUintptr(outBuf.PvBuffer)), outBuf.CbBuffer)
			if err := sock.Send(outSlice); err != nil {
				wc.CallG0(sspiTable.FreeContextBuffer, outBuf.PvBuffer)
				return fmt.Errorf("tls handshake send: %w", err)
			}
			wc.CallG0(sspiTable.FreeContextBuffer, outBuf.PvBuffer)
		}

		ss := int32(status)
		if ss == SEC_E_OK {
			break
		}

		if status == uintptr(uint32(SEC_I_CONTINUE_NEEDED)) || ss == SEC_E_INCOMPLETE_MESSAGE {
			if inBufs[1].BufferType == SECBUFFER_EXTRA {
				extra := inBufs[1].CbBuffer
				copy(data[:extra], data[dataLen-extra:dataLen])
				dataLen = extra
			} else {
				dataLen = 0
			}
			if int(dataLen) >= bufSize {
				return errors.New("tls handshake: buffer overflow")
			}
			n, err := sock.Recv(data[dataLen:])
			if err != nil {
				return fmt.Errorf("tls handshake recv: %w", err)
			}
			if n == 0 {
				return errors.New("tls handshake: connection closed")
			}
			dataLen += uint32(n)
		} else {
			return fmt.Errorf("tls handshake failed: 0x%x", status)
		}

		runtime.KeepAlive(inBufs)
		runtime.KeepAlive(inDesc)
		runtime.KeepAlive(outBuf)
		runtime.KeepAlive(outDesc)
		runtime.KeepAlive(expiry)
	}

	ret, _, _ := wc.CallG0(sspiTable.QueryContextAttributesW,
		uintptr(unsafePointer(&client.ContextHandle)),
		uintptr(SECPKG_ATTR_STREAM_SIZES),
		uintptr(unsafePointer(&client.Sizes)))
	if int32(ret) != 0 {
		return fmt.Errorf("QueryContextAttributes StreamSizes failed: 0x%x", ret)
	}

	return nil
}

