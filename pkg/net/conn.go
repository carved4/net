package net

import (
	"errors"
	"fmt"
	"sync"

	wc "github.com/carved4/go-wincall"
)

type TLSConn struct {
	sock      *afdSocket
	tlsClient *TLSClient
	host      string
	closed    bool
	mu        sync.Mutex
}

func Dial(host string, port uint16, config *ClientConfig) (*TLSConn, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := initSSPI(); err != nil {
		return nil, newNetError(ErrSSPIInit, "sspi init", err)
	}
	if err := initCrypt32(); err != nil {
		return nil, newNetError(ErrCrypt32Init, "crypt32 init", err)
	}

	resolver := NewDNSResolver()
	ip, err := resolver.Resolve(host)
	if err != nil {
		return nil, newNetError(ErrDNSResolution, "dns resolve", err)
	}

	sock, err := afdCreateTCPSocket()
	if err != nil {
		return nil, newNetError(ErrSocketCreate, "socket create", err)
	}

	if err := sock.Bind(); err != nil {
		sock.Close()
		return nil, newNetError(ErrSocketBind, "socket bind", err)
	}
	if err := sock.Connect(ip, port); err != nil {
		sock.Close()
		return nil, newNetError(ErrConnection, "connect", err)
	}

	tlsClient := new(TLSClient)
	if err := tlsAcquireCredentials(tlsClient); err != nil {
		sock.Close()
		return nil, newNetError(ErrTLSHandshake, "tls credentials", err)
	}

	hostW, _ := wc.UTF16ptr(host)
	if config.TLS.ServerName != "" {
		hostW, _ = wc.UTF16ptr(config.TLS.ServerName)
	}

	if config.TLS.SkipVerify {
		if err := tlsHandshakeNoVerify(tlsClient, sock, hostW); err != nil {
			tlsFreeClient(tlsClient)
			sock.Close()
			return nil, newNetError(ErrTLSHandshake, "tls handshake", err)
		}
	} else {
		if err := tlsHandshake(tlsClient, sock, hostW); err != nil {
			tlsFreeClient(tlsClient)
			sock.Close()
			return nil, newNetError(ErrTLSHandshake, "tls handshake", err)
		}
	}

	return &TLSConn{
		sock:      sock,
		tlsClient: tlsClient,
		host:      host,
	}, nil
}

func (c *TLSConn) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("connection closed")
	}
	return tlsSend(c.tlsClient, c.sock, data)
}

func (c *TLSConn) Recv() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("connection closed")
	}
	return tlsRecvRaw(c.tlsClient, c.sock)
}

func (c *TLSConn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	tlsFreeClient(c.tlsClient)
	c.sock.Close()
}

type RawConn struct {
	sock   *afdSocket
	closed bool
	mu     sync.Mutex
}

func DialRaw(host string, port uint16, config *ClientConfig) (*RawConn, error) {
	if config == nil {
		config = DefaultConfig()
	}

	resolver := NewDNSResolver()
	ip, err := resolver.Resolve(host)
	if err != nil {
		return nil, newNetError(ErrDNSResolution, "dns resolve", err)
	}

	sock, err := afdCreateTCPSocket()
	if err != nil {
		return nil, newNetError(ErrSocketCreate, "socket create", err)
	}

	if err := sock.Bind(); err != nil {
		sock.Close()
		return nil, newNetError(ErrSocketBind, "socket bind", err)
	}
	if err := sock.Connect(ip, port); err != nil {
		sock.Close()
		return nil, newNetError(ErrConnection, "connect", err)
	}

	return &RawConn{sock: sock}, nil
}

func DialRawIP(ip uint32, port uint16) (*RawConn, error) {
	sock, err := afdCreateTCPSocket()
	if err != nil {
		return nil, newNetError(ErrSocketCreate, "socket create", err)
	}

	if err := sock.Bind(); err != nil {
		sock.Close()
		return nil, newNetError(ErrSocketBind, "socket bind", err)
	}
	if err := sock.Connect(ip, port); err != nil {
		sock.Close()
		return nil, newNetError(ErrConnection, "connect", err)
	}

	return &RawConn{sock: sock}, nil
}

func (c *RawConn) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("connection closed")
	}
	return c.sock.Send(data)
}

func (c *RawConn) Recv(buf []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("connection closed")
	}
	return c.sock.Recv(buf)
}

func (c *RawConn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.sock.Close()
}


type ConnPool struct {
	conns  map[string]*TLSConn
	config *ClientConfig
	mu     sync.Mutex
}

func NewConnPool(config *ClientConfig) *ConnPool {
	if config == nil {
		config = DefaultConfig()
	}
	return &ConnPool{
		conns:  make(map[string]*TLSConn),
		config: config,
	}
}

func (p *ConnPool) Get(host string, port uint16) (*TLSConn, error) {
	key := fmt.Sprintf("%s:%d", host, port)
	p.mu.Lock()
	if conn, ok := p.conns[key]; ok {
		delete(p.conns, key)
		p.mu.Unlock()
		return conn, nil
	}
	p.mu.Unlock()
	return Dial(host, port, p.config)
}

func (p *ConnPool) Put(conn *TLSConn, port uint16) {
	if conn == nil {
		return
	}
	conn.mu.Lock()
	closed := conn.closed
	conn.mu.Unlock()
	if closed {
		return
	}
	key := fmt.Sprintf("%s:%d", conn.host, port)
	p.mu.Lock()
	if existing, ok := p.conns[key]; ok {
		existing.Close()
	}
	p.conns[key] = conn
	p.mu.Unlock()
}

func (p *ConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		conn.Close()
	}
	p.conns = make(map[string]*TLSConn)
}

