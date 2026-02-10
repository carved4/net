package net

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

const (
	SOCK_DGRAM	= 2
	IPPROTO_UDP	= 17

	IOCTL_AFD_SEND_DATAGRAM	= 0x00012023
	IOCTL_AFD_RECV_DATAGRAM	= 0x0001201B
)

type AFD_WSABUF struct {
	Len	uint32
	_	uint32
	Buf	uintptr
}

type TDI_CONNECTION_INFORMATION struct {
	UserDataLength	uintptr
	UserData	uintptr
	OptionsLength	uintptr
	Options		uintptr
	RemoteAddress	uintptr
	RemoteAddrLen	uintptr
}

type AFD_SEND_INFO_UDP struct {
	BufferArray	*AFD_WSABUF
	BufferCount	uint32
	AfdFlags	uint32
	TdiRequest	[24]byte
	TdiConnection	TDI_CONNECTION_INFORMATION
}

type AFD_RECV_INFO_UDP struct {
	BufferArray	*AFD_WSABUF
	BufferCount	uint32
	AfdFlags	uint32
	TdiFlags	uint32
	_		uint32
	Address		uintptr
	AddressLength	uintptr
}

type afdUDPSocket struct {
	handle uintptr
}

func afdCreateUDPSocket() (*afdUDPSocket, error) {
	eaName := [16]byte{'A', 'f', 'd', 'O', 'p', 'e', 'n', 'P', 'a', 'c', 'k', 'e', 't', 'X', 'X', 0}
	ea := new(AFD_OPEN_PACKET_EXTENDED_ATTRIBUTES)
	ea.ExtendedAttributeNameLength = 15
	ea.ExtendedAttributeValueLength = 30
	ea.AddressFamily = AF_INET
	ea.SocketType = SOCK_DGRAM
	ea.Protocol = IPPROTO_UDP
	ea.ExtendedAttributeName = eaName
	ea.EndpointFlags = 0x1
	for i := range ea.Unknown1 {
		ea.Unknown1[i] = 0xff
	}

	devicePath, _ := wc.UTF16ptr(`\Device\Afd\Endpoint`)
	ustr := new(UNICODE_STRING)
	ustr.Buffer = devicePath
	pathLen := 0
	for p := devicePath; *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(pathLen*2))) != 0; pathLen++ {
	}
	ustr.Length = uint16(pathLen * 2)
	ustr.MaximumLength = ustr.Length + 2

	oa := new(OBJECT_ATTRIBUTES)
	oa.Length = uint32(unsafe.Sizeof(*oa))
	oa.ObjectName = ustr
	oa.Attributes = OBJ_CASE_INSENSITIVE

	handle := new(uintptr)
	iosb := new(IO_STATUS_BLOCK)
	accessMask := uintptr(0x80000000 | 0x40000000 | 0x00100000)

	ret, _ := wc.IndirectSyscall(ntCreateFile.SSN, ntCreateFile.Address,
		uintptr(unsafe.Pointer(handle)),
		accessMask,
		uintptr(unsafe.Pointer(oa)),
		uintptr(unsafe.Pointer(iosb)),
		0, 0,
		uintptr(0x00000001|0x00000002),
		uintptr(FILE_OPEN_IF),
		uintptr(FILE_SYNCHRONOUS_IO_NONALERT),
		uintptr(unsafe.Pointer(ea)),
		uintptr(unsafe.Sizeof(*ea)))
	if int32(ret) < 0 {
		return nil, fmt.Errorf("NtCreateFile AFD UDP failed: 0x%x", ret)
	}
	runtime.KeepAlive(oa)
	runtime.KeepAlive(ustr)
	runtime.KeepAlive(ea)
	runtime.KeepAlive(devicePath)
	return &afdUDPSocket{handle: *handle}, nil
}

func (s *afdUDPSocket) Close() {
	if s.handle != 0 {
		wc.Call("kernel32.dll", "CloseHandle", s.handle)
		s.handle = 0
	}
}

func (s *afdUDPSocket) Bind() error {
	bind := new(AFD_BIND_SOCKET)
	bind.Address.Sin_family = AF_INET
	out := make([]byte, 16)
	_, err := afdIoctl(s.handle, IOCTL_AFD_BIND, unsafe.Pointer(bind), uint32(unsafe.Sizeof(*bind)), unsafe.Pointer(&out[0]), uint32(len(out)))
	runtime.KeepAlive(bind)
	runtime.KeepAlive(out)
	return err
}

type TRANSPORT_ADDRESS struct {
	AddressCount	int32
	AddressLength	uint16
	AddressType	uint16
	Address		SOCKADDR_IN
}

func (s *afdUDPSocket) SendTo(data []byte, ip uint32, port uint16) error {
	if len(data) == 0 {
		return nil
	}

	taddr := new(TRANSPORT_ADDRESS)
	taddr.AddressCount = 1
	taddr.AddressLength = 16
	taddr.AddressType = AF_INET
	taddr.Address.Sin_family = AF_INET
	taddr.Address.Sin_addr.S_addr = ip
	taddr.Address.Sin_port = htons(port)

	wsaBuf := new(AFD_WSABUF)
	wsaBuf.Len = uint32(len(data))
	wsaBuf.Buf = uintptr(unsafe.Pointer(&data[0]))

	req := new(AFD_SEND_INFO_UDP)
	req.BufferArray = wsaBuf
	req.BufferCount = 1
	req.AfdFlags = 0
	req.TdiConnection.RemoteAddress = uintptr(unsafe.Pointer(taddr))
	req.TdiConnection.RemoteAddrLen = uintptr(unsafe.Sizeof(*taddr))

	out := make([]byte, 16)
	_, err := afdIoctl(s.handle, IOCTL_AFD_SEND_DATAGRAM, unsafe.Pointer(req), uint32(unsafe.Sizeof(*req)), unsafe.Pointer(&out[0]), uint32(len(out)))
	runtime.KeepAlive(wsaBuf)
	runtime.KeepAlive(req)
	runtime.KeepAlive(taddr)
	runtime.KeepAlive(out)
	runtime.KeepAlive(data)
	return err
}

func (s *afdUDPSocket) RecvFrom(buf []byte) (int, uint32, uint16, error) {
	if len(buf) == 0 {
		return 0, 0, 0, nil
	}

	taddr := new(TRANSPORT_ADDRESS)
	addrLen := uint32(unsafe.Sizeof(*taddr))

	wsaBuf := new(AFD_WSABUF)
	wsaBuf.Len = uint32(len(buf))
	wsaBuf.Buf = uintptr(unsafe.Pointer(&buf[0]))

	req := new(AFD_RECV_INFO_UDP)
	req.BufferArray = wsaBuf
	req.BufferCount = 1
	req.AfdFlags = 0
	req.TdiFlags = 0x20
	req.Address = uintptr(unsafe.Pointer(taddr))
	req.AddressLength = uintptr(unsafe.Pointer(&addrLen))

	out := make([]byte, 16)
	info, err := afdIoctl(s.handle, IOCTL_AFD_RECV_DATAGRAM, unsafe.Pointer(req), uint32(unsafe.Sizeof(*req)), unsafe.Pointer(&out[0]), uint32(len(out)))
	runtime.KeepAlive(wsaBuf)
	runtime.KeepAlive(req)
	runtime.KeepAlive(taddr)
	runtime.KeepAlive(out)
	if err != nil {
		return 0, 0, 0, err
	}
	return int(info), taddr.Address.Sin_addr.S_addr, htons(taddr.Address.Sin_port), nil
}

func (s *afdUDPSocket) Connect(ip uint32, port uint16) error {
	req := new(AFD_CONNECT_REQUEST_IPV4)
	req.Address.Sin_family = AF_INET
	req.Address.Sin_addr.S_addr = ip
	req.Address.Sin_port = htons(port)
	_, err := afdIoctl(s.handle, IOCTL_AFD_CONNECT, unsafe.Pointer(req), uint32(unsafe.Sizeof(*req)), nil, 0)
	runtime.KeepAlive(req)
	return err
}

func (s *afdUDPSocket) Send(data []byte) error {
	offset := 0
	for offset < len(data) {
		ioBuf := new(AFD_IO_BUFFER)
		ioBuf.Length = uint32(len(data) - offset)
		ioBuf.Buffer = uintptr(unsafe.Pointer(&data[offset]))
		req := new(AFD_TRANSFER_REQUEST)
		req.Buffer = ioBuf
		req.BufferCount = 1
		out := make([]byte, 16)
		info, err := afdIoctl(s.handle, IOCTL_AFD_SEND, unsafe.Pointer(req), uint32(unsafe.Sizeof(*req)), unsafe.Pointer(&out[0]), uint32(len(out)))
		if err != nil {
			return err
		}
		sent := int(info)
		if sent == 0 {
			return fmt.Errorf("udp send: 0 bytes sent")
		}
		offset += sent
		runtime.KeepAlive(ioBuf)
		runtime.KeepAlive(req)
		runtime.KeepAlive(out)
	}
	runtime.KeepAlive(data)
	return nil
}

func (s *afdUDPSocket) Recv(buf []byte) (int, error) {
	ioBuf := new(AFD_IO_BUFFER)
	ioBuf.Length = uint32(len(buf))
	ioBuf.Buffer = uintptr(unsafe.Pointer(&buf[0]))
	req := new(AFD_TRANSFER_REQUEST)
	req.Buffer = ioBuf
	req.BufferCount = 1
	req.TdiFlags = 0x20
	out := make([]byte, 16)
	info, err := afdIoctl(s.handle, IOCTL_AFD_RECV, unsafe.Pointer(req), uint32(unsafe.Sizeof(*req)), unsafe.Pointer(&out[0]), uint32(len(out)))
	runtime.KeepAlive(ioBuf)
	runtime.KeepAlive(req)
	runtime.KeepAlive(out)
	if err != nil {
		return 0, err
	}
	return int(info), nil
}

type ConnectedUDPConn struct {
	sock	*afdUDPSocket
	closed	bool
	mu	sync.Mutex
}

func DialUDPConnected(host string, port uint16, config *ClientConfig) (*ConnectedUDPConn, error) {
	if config == nil {
		config = DefaultConfig()
	}

	resolver := NewDNSResolver()
	ip, err := resolver.Resolve(host)
	if err != nil {
		return nil, newNetError(ErrDNSResolution, "dns resolve", err)
	}

	return DialUDPConnectedIP(ip, port)
}

func DialUDPConnectedIP(ip uint32, port uint16) (*ConnectedUDPConn, error) {
	sock, err := afdCreateUDPSocket()
	if err != nil {
		return nil, newNetError(ErrSocketCreate, "udp socket create", err)
	}

	if err := sock.Bind(); err != nil {
		sock.Close()
		return nil, newNetError(ErrSocketBind, "udp socket bind", err)
	}

	if err := sock.Connect(ip, port); err != nil {
		sock.Close()
		return nil, newNetError(ErrConnection, "udp connect", err)
	}

	return &ConnectedUDPConn{sock: sock}, nil
}

func (c *ConnectedUDPConn) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("connection closed")
	}
	return c.sock.Send(data)
}

func (c *ConnectedUDPConn) Recv(buf []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}
	return c.sock.Recv(buf)
}

func (c *ConnectedUDPConn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.sock.Close()
}

