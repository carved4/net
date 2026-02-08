package net

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

const (
	AF_INET     = 2
	SOCK_STREAM = 1
	IPPROTO_TCP = 6

	IOCTL_AFD_BIND    = 0x00012003
	IOCTL_AFD_CONNECT = 0x00012007
	IOCTL_AFD_SEND    = 0x0001201F
	IOCTL_AFD_RECV    = 0x00012017

	OBJ_CASE_INSENSITIVE         = 0x00000040
	FILE_OPEN_IF                 = 0x00000003
	FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

	EVENT_ALL_ACCESS = 0x1F0003
)

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	_                        uint32 // padding on x64
	RootDirectory            uintptr
	ObjectName               *UNICODE_STRING
	Attributes               uint32
	_                        uint32 // padding on x64
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type IO_STATUS_BLOCK struct {
	Status      uintptr
	Information uintptr
}

type IN_ADDR struct {
	S_addr uint32
}

type SOCKADDR_IN struct {
	Sin_family int16
	Sin_port   uint16
	Sin_addr   IN_ADDR
	Sin_zero   [8]byte
}

type AFD_OPEN_PACKET_EXTENDED_ATTRIBUTES struct {
	NextEntryOffset              uint32
	Flags                        byte
	ExtendedAttributeNameLength  byte
	ExtendedAttributeValueLength uint16
	ExtendedAttributeName        [16]byte
	EndpointFlags                uint32
	GroupID                      uint32
	AddressFamily                uint32
	SocketType                   uint32
	Protocol                     uint32
	SizeOfTransportName          uint32
	Unknown1                     [9]byte
}

type AFD_BIND_SOCKET struct {
	Flags   uint32
	Address SOCKADDR_IN
}

type AFD_CONNECT_REQUEST_IPV4 struct {
	SharedAccessNamespaceActive uint64
	RootEndpoint                uint64
	ConnectEndpoint             uint64
	Address                     SOCKADDR_IN
}

type AFD_IO_BUFFER struct {
	Length uint32
	_      uint32 // padding on x64
	Buffer uintptr
}

type AFD_TRANSFER_REQUEST struct {
	Buffer      *AFD_IO_BUFFER
	BufferCount uint32
	AfdFlags    uint32
	TdiFlags    uint32
}

const (
	SECBUFFER_VERSION        = 0
	SECBUFFER_EMPTY          = 0
	SECBUFFER_DATA           = 1
	SECBUFFER_TOKEN          = 2
	SECBUFFER_EXTRA          = 5
	SECBUFFER_STREAM_TRAILER = 6
	SECBUFFER_STREAM_HEADER  = 7

	SECURITY_NATIVE_DREP            = 0x00000010
	SECPKG_ATTR_STREAM_SIZES        = 4
	SECPKG_ATTR_REMOTE_CERT_CONTEXT = 0x53

	ISC_REQ_REPLAY_DETECT   = 0x00000004
	ISC_REQ_SEQUENCE_DETECT = 0x00000008
	ISC_REQ_CONFIDENTIALITY = 0x00000010
	ISC_REQ_ALLOCATE_MEMORY = 0x00000100
	ISC_REQ_EXTENDED_ERROR  = 0x00004000
	ISC_REQ_STREAM          = 0x00008000

	SCHANNEL_CRED_VERSION = 0x00000004
	SCHANNEL_SHUTDOWN     = 0x00000001

	SEC_E_OK                 = 0
	SEC_I_CONTINUE_NEEDED    = 0x00090312
	SEC_E_INCOMPLETE_MESSAGE = int32(-2146893032) // 0x80090318
	SEC_I_CONTEXT_EXPIRED    = 0x00090317
	SEC_I_RENEGOTIATE        = 0x00090321

	AUTHTYPE_SERVER = 1
)

type SecHandle struct {
	DwLower uintptr
	DwUpper uintptr
}

type SecBuffer struct {
	CbBuffer   uint32
	BufferType uint32
	PvBuffer   uintptr
}

type SecBufferDesc struct {
	UlVersion uint32
	CBuffers  uint32
	PBuffers  *SecBuffer
}

type SECURITY_INTEGER struct {
	LowPart  uint32
	HighPart uint32
}

type SecPkgContext_StreamSizes struct {
	CbHeader         uint32
	CbTrailer        uint32
	CbMaximumMessage uint32
	CBuffers         uint32
	CbBlockSize      uint32
}

type SCHANNEL_CRED struct {
	DwVersion               uint32
	CCreds                  uint32
	PaCred                  uintptr
	HRootStore              uintptr
	CMappers                uint32
	_                       uint32 // padding
	AphMappers              uintptr
	CSupportedAlgs          uint32
	_                       uint32 // padding
	PalgSupportedAlgs       uintptr
	GrbitEnabledProtocols   uint32
	DwMinimumCipherStrength uint32
	DwMaximumCipherStrength uint32
	DwSessionLifespan       uint32
	DwFlags                 uint32
	DwCredFormat            uint32
}

type SecurityFunctionTableW struct {
	DwVersion                   uint32
	_                           uint32 // padding
	EnumerateSecurityPackagesW  uintptr
	QueryCredentialsAttributesW uintptr
	AcquireCredentialsHandleW   uintptr
	FreeCredentialsHandle       uintptr
	Reserved2                   uintptr
	InitializeSecurityContextW  uintptr
	AcceptSecurityContext       uintptr
	CompleteAuthToken           uintptr
	DeleteSecurityContext       uintptr
	ApplyControlToken           uintptr
	QueryContextAttributesW     uintptr
	ImpersonateSecurityContext  uintptr
	RevertSecurityContext       uintptr
	MakeSignature               uintptr
	VerifySignature             uintptr
	FreeContextBuffer           uintptr
	QuerySecurityPackageInfoW   uintptr
	Reserved3                   uintptr
	Reserved4                   uintptr
	ExportSecurityContext       uintptr
	ImportSecurityContextW      uintptr
	AddCredentialsW             uintptr
	Reserved8                   uintptr
	QuerySecurityContextToken   uintptr
	EncryptMessage              uintptr
	DecryptMessage              uintptr
	SetContextAttributesW       uintptr
	SetCredentialsAttributesW   uintptr
	Reserved9                   uintptr
}

type TLSClient struct {
	CredentialHandle      SecHandle
	ContextHandle         SecHandle
	CredentialInitialized bool
	ContextInitialized    bool
	Sizes                 SecPkgContext_StreamSizes
}

type CERT_CHAIN_PARA struct {
	CbSize uint32
	_      [108]byte
}

type SSL_EXTRA_CERT_CHAIN_POLICY_PARA struct {
	CbSize         uint32
	DwAuthType     uint32
	FdwChecks      uint32
	_              uint32 // padding
	PwszServerName *uint16
}

type CERT_CHAIN_POLICY_PARA struct {
	CbSize            uint32
	DwFlags           uint32
	PvExtraPolicyPara uintptr
}

type CERT_CHAIN_POLICY_STATUS struct {
	CbSize              uint32
	DwError             uint32
	LChainIndex         int32
	LElementIndex       int32
	PvExtraPolicyStatus uintptr
}

type DNS_HEADER struct {
	Id      uint16
	Flags   uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }
func htonl(v uint32) uint32 {
	return ((v & 0x000000FF) << 24) | ((v & 0x0000FF00) << 8) |
		((v & 0x00FF0000) >> 8) | ((v & 0xFF000000) >> 24)
}

var (
	ntCreateFile          = wc.GetSyscall(wc.GetHash("NtCreateFile"))
	ntDeviceIoControlFile = wc.GetSyscall(wc.GetHash("NtDeviceIoControlFile"))
	ntWaitForSingleObject = wc.GetSyscall(wc.GetHash("NtWaitForSingleObject"))
)

var sspiTable *SecurityFunctionTableW

var (
	sspiOnce    sync.Once
	sspiInitErr error
)

func initSSPI() error {
	sspiOnce.Do(func() {
		wc.LoadLibraryLdr("sspicli.dll")
		base := wc.GetModuleBase(wc.GetHash("sspicli.dll"))
		if base == 0 {
			sspiInitErr = errors.New("failed to load sspicli.dll")
			return
		}
		initSecIfaceW := wc.GetFunctionAddress(base, wc.GetHash("InitSecurityInterfaceW"))
		if initSecIfaceW == 0 {
			sspiInitErr = errors.New("InitSecurityInterfaceW not found")
			return
		}
		tablePtr, _, _ := wc.CallG0(initSecIfaceW)
		if tablePtr == 0 {
			sspiInitErr = errors.New("InitSecurityInterfaceW returned NULL")
			return
		}
		sspiTable = (*SecurityFunctionTableW)(unsafe.Pointer(tablePtr))
	})
	return sspiInitErr
}

var (
	certGetCertificateChain          uintptr
	certVerifyCertificateChainPolicy uintptr
	certFreeCertificateChain         uintptr
	certFreeCertificateContext       uintptr
)

var (
	crypt32Once    sync.Once
	crypt32InitErr error
)

func initCrypt32() error {
	crypt32Once.Do(func() {
		wc.LoadLibraryLdr("crypt32.dll")
		base := wc.GetModuleBase(wc.GetHash("crypt32.dll"))
		if base == 0 {
			crypt32InitErr = errors.New("failed to load crypt32.dll")
			return
		}
		certGetCertificateChain = wc.GetFunctionAddress(base, wc.GetHash("CertGetCertificateChain"))
		certVerifyCertificateChainPolicy = wc.GetFunctionAddress(base, wc.GetHash("CertVerifyCertificateChainPolicy"))
		certFreeCertificateChain = wc.GetFunctionAddress(base, wc.GetHash("CertFreeCertificateChain"))
		certFreeCertificateContext = wc.GetFunctionAddress(base, wc.GetHash("CertFreeCertificateContext"))
		if certGetCertificateChain == 0 || certVerifyCertificateChainPolicy == 0 ||
			certFreeCertificateChain == 0 || certFreeCertificateContext == 0 {
			crypt32InitErr = errors.New("failed to resolve crypt32 functions")
			return
		}
	})
	return crypt32InitErr
}


type afdSocket struct {
	handle uintptr
}

func afdIoctl(sock uintptr, ioctl uint32, inBuf unsafe.Pointer, inLen uint32, outBuf unsafe.Pointer, outLen uint32) (uintptr, error) {
	iosb := new(IO_STATUS_BLOCK)
	const STATUS_PENDING = 0x00000103
	ret, _ := wc.IndirectSyscall(ntDeviceIoControlFile.SSN, ntDeviceIoControlFile.Address,
		sock, 0, 0, 0,
		uintptr(unsafe.Pointer(iosb)),
		uintptr(ioctl),
		uintptr(inBuf), uintptr(inLen),
		uintptr(outBuf), uintptr(outLen))
	if ret == STATUS_PENDING {
		wc.IndirectSyscall(ntWaitForSingleObject.SSN, ntWaitForSingleObject.Address, sock, 0, 0)
		ret = uintptr(iosb.Status)
	}
	runtime.KeepAlive(iosb)
	if int32(ret) < 0 {
		return 0, fmt.Errorf("NtDeviceIoControlFile failed: 0x%x", ret)
	}
	return iosb.Information, nil
}

func afdCreateTCPSocket() (*afdSocket, error) {
	eaName := [16]byte{'A', 'f', 'd', 'O', 'p', 'e', 'n', 'P', 'a', 'c', 'k', 'e', 't', 'X', 'X', 0}
	ea := new(AFD_OPEN_PACKET_EXTENDED_ATTRIBUTES)
	ea.ExtendedAttributeNameLength = 15
	ea.ExtendedAttributeValueLength = 30
	ea.AddressFamily = AF_INET
	ea.SocketType = SOCK_STREAM
	ea.Protocol = IPPROTO_TCP
	ea.ExtendedAttributeName = eaName
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
		return nil, fmt.Errorf("NtCreateFile AFD failed: 0x%x", ret)
	}
	runtime.KeepAlive(oa)
	runtime.KeepAlive(ustr)
	runtime.KeepAlive(ea)
	runtime.KeepAlive(devicePath)
	return &afdSocket{handle: *handle}, nil
}

func (s *afdSocket) Close() {
	if s.handle != 0 {
		wc.Call("kernel32.dll", "CloseHandle", s.handle)
		s.handle = 0
	}
}

func (s *afdSocket) Bind() error {
	bind := new(AFD_BIND_SOCKET)
	bind.Address.Sin_family = AF_INET
	out := make([]byte, 16)
	_, err := afdIoctl(s.handle, IOCTL_AFD_BIND, unsafe.Pointer(bind), uint32(unsafe.Sizeof(*bind)), unsafe.Pointer(&out[0]), uint32(len(out)))
	runtime.KeepAlive(bind)
	runtime.KeepAlive(out)
	return err
}

func (s *afdSocket) Connect(ip uint32, port uint16) error {
	req := new(AFD_CONNECT_REQUEST_IPV4)
	req.Address.Sin_family = AF_INET
	req.Address.Sin_addr.S_addr = ip
	req.Address.Sin_port = htons(port)
	_, err := afdIoctl(s.handle, IOCTL_AFD_CONNECT, unsafe.Pointer(req), uint32(unsafe.Sizeof(*req)), nil, 0)
	runtime.KeepAlive(req)
	return err
}

func (s *afdSocket) Send(data []byte) error {
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
			return errors.New("afd send: 0 bytes sent")
		}
		offset += sent
		runtime.KeepAlive(ioBuf)
		runtime.KeepAlive(req)
		runtime.KeepAlive(out)
	}
	runtime.KeepAlive(data)
	return nil
}

func (s *afdSocket) Recv(buf []byte) (int, error) {
	ioBuf := new(AFD_IO_BUFFER)
	ioBuf.Length = uint32(len(buf))
	ioBuf.Buffer = uintptr(unsafe.Pointer(&buf[0]))
	req := new(AFD_TRANSFER_REQUEST)
	req.Buffer = ioBuf
	req.BufferCount = 1
	req.TdiFlags = 32
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

func tlsAcquireCredentials(client *TLSClient) error {
	cred := new(SCHANNEL_CRED)
	cred.DwVersion = SCHANNEL_CRED_VERSION

	providerName, _ := wc.UTF16ptr("Microsoft Unified Security Protocol Provider")
	expiry := new(SECURITY_INTEGER)

	ret, _, _ := wc.CallG0(sspiTable.AcquireCredentialsHandleW,
		0,
		uintptr(unsafe.Pointer(providerName)),
		uintptr(2), // SECPKG_CRED_OUTBOUND
		0,
		uintptr(unsafe.Pointer(cred)),
		0, 0,
		uintptr(unsafe.Pointer(&client.CredentialHandle)),
		uintptr(unsafe.Pointer(expiry)))
	runtime.KeepAlive(cred)
	runtime.KeepAlive(providerName)
	runtime.KeepAlive(expiry)
	if int32(ret) != 0 {
		return fmt.Errorf("AcquireCredentialsHandle failed: 0x%x", ret)
	}
	client.CredentialInitialized = true
	return nil
}

func tlsFreeClient(client *TLSClient) {
	if client.ContextInitialized {
		wc.CallG0(sspiTable.DeleteSecurityContext, uintptr(unsafe.Pointer(&client.ContextHandle)))
		client.ContextInitialized = false
	}
	if client.CredentialInitialized {
		wc.CallG0(sspiTable.FreeCredentialsHandle, uintptr(unsafe.Pointer(&client.CredentialHandle)))
		client.CredentialInitialized = false
	}
}

func tlsHandshake(client *TLSClient, sock *afdSocket, hostW *uint16) error {
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
			inBufs[0].PvBuffer = uintptr(unsafe.Pointer(&data[0]))
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
				uintptr(unsafe.Pointer(&client.CredentialHandle)),
				0,
				uintptr(unsafe.Pointer(hostW)),
				contextReq, 0,
				uintptr(SECURITY_NATIVE_DREP),
				0, 0,
				uintptr(unsafe.Pointer(&client.ContextHandle)),
				uintptr(unsafe.Pointer(outDesc)),
				uintptr(unsafe.Pointer(attrs)),
				uintptr(unsafe.Pointer(expiry)))
			client.ContextInitialized = true
		} else {
			status, _, _ = wc.CallG0(sspiTable.InitializeSecurityContextW,
				uintptr(unsafe.Pointer(&client.CredentialHandle)),
				uintptr(unsafe.Pointer(&client.ContextHandle)),
				uintptr(unsafe.Pointer(hostW)),
				contextReq, 0,
				uintptr(SECURITY_NATIVE_DREP),
				uintptr(unsafe.Pointer(inDesc)),
				0, 0,
				uintptr(unsafe.Pointer(outDesc)),
				uintptr(unsafe.Pointer(attrs)),
				uintptr(unsafe.Pointer(expiry)))
		}

		if outBuf.PvBuffer != 0 && outBuf.CbBuffer > 0 {
			outSlice := unsafe.Slice((*byte)(unsafe.Pointer(outBuf.PvBuffer)), outBuf.CbBuffer)
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
		uintptr(unsafe.Pointer(&client.ContextHandle)),
		uintptr(SECPKG_ATTR_STREAM_SIZES),
		uintptr(unsafe.Pointer(&client.Sizes)))
	if int32(ret) != 0 {
		return fmt.Errorf("QueryContextAttributes StreamSizes failed: 0x%x", ret)
	}

	if err := tlsVerifyCert(client, hostW); err != nil {
		return err
	}

	return nil
}

func tlsVerifyCert(client *TLSClient, hostW *uint16) error {
	serverCert := new(uintptr)
	ret, _, _ := wc.CallG0(sspiTable.QueryContextAttributesW,
		uintptr(unsafe.Pointer(&client.ContextHandle)),
		uintptr(SECPKG_ATTR_REMOTE_CERT_CONTEXT),
		uintptr(unsafe.Pointer(serverCert)))
	if int32(ret) != 0 || *serverCert == 0 {
		return fmt.Errorf("failed to get server cert: 0x%x", ret)
	}
	defer wc.CallG0(certFreeCertificateContext, *serverCert)

	hCertStore := *(*uintptr)(unsafe.Pointer(*serverCert + 32))

	chainPara := new(CERT_CHAIN_PARA)
	chainPara.CbSize = uint32(unsafe.Sizeof(*chainPara))

	chainCtx := new(uintptr)
	ok, _, _ := wc.CallG0(certGetCertificateChain,
		0, *serverCert, 0, hCertStore,
		uintptr(unsafe.Pointer(chainPara)),
		0, 0,
		uintptr(unsafe.Pointer(chainCtx)))
	if ok == 0 || *chainCtx == 0 {
		return errors.New("CertGetCertificateChain failed")
	}
	defer wc.CallG0(certFreeCertificateChain, *chainCtx)

	extra := new(SSL_EXTRA_CERT_CHAIN_POLICY_PARA)
	extra.CbSize = uint32(unsafe.Sizeof(*extra))
	extra.DwAuthType = AUTHTYPE_SERVER
	extra.PwszServerName = hostW

	policy := new(CERT_CHAIN_POLICY_PARA)
	policy.CbSize = uint32(unsafe.Sizeof(*policy))
	policy.PvExtraPolicyPara = uintptr(unsafe.Pointer(extra))

	policyStatus := new(CERT_CHAIN_POLICY_STATUS)
	policyStatus.CbSize = uint32(unsafe.Sizeof(*policyStatus))

	ok, _, _ = wc.CallG0(certVerifyCertificateChainPolicy,
		uintptr(4), *chainCtx,
		uintptr(unsafe.Pointer(policy)),
		uintptr(unsafe.Pointer(policyStatus)))
	if ok == 0 {
		return errors.New("CertVerifyCertificateChainPolicy call failed")
	}
	if policyStatus.DwError != 0 {
		return fmt.Errorf("cert policy error: 0x%x", policyStatus.DwError)
	}

	runtime.KeepAlive(chainPara)
	runtime.KeepAlive(extra)
	runtime.KeepAlive(policy)
	runtime.KeepAlive(policyStatus)
	return nil
}

func tlsSend(client *TLSClient, sock *afdSocket, plaintext []byte) error {
	offset := 0
	for offset < len(plaintext) {
		maxFrag := int(client.Sizes.CbMaximumMessage)
		fragLen := len(plaintext) - offset
		if fragLen > maxFrag {
			fragLen = maxFrag
		}
		totalBuf := int(client.Sizes.CbHeader) + fragLen + int(client.Sizes.CbTrailer)
		buf := make([]byte, totalBuf)
		copy(buf[client.Sizes.CbHeader:], plaintext[offset:offset+fragLen])

		secBufs := new([4]SecBuffer)
		secBufs[0] = SecBuffer{CbBuffer: client.Sizes.CbHeader, BufferType: SECBUFFER_STREAM_HEADER, PvBuffer: uintptr(unsafe.Pointer(&buf[0]))}
		secBufs[1] = SecBuffer{CbBuffer: uint32(fragLen), BufferType: SECBUFFER_DATA, PvBuffer: uintptr(unsafe.Pointer(&buf[client.Sizes.CbHeader]))}
		secBufs[2] = SecBuffer{CbBuffer: client.Sizes.CbTrailer, BufferType: SECBUFFER_STREAM_TRAILER, PvBuffer: uintptr(unsafe.Pointer(&buf[int(client.Sizes.CbHeader)+fragLen]))}
		secBufs[3] = SecBuffer{BufferType: SECBUFFER_EMPTY}
		desc := &SecBufferDesc{UlVersion: SECBUFFER_VERSION, CBuffers: 4, PBuffers: &secBufs[0]}

		ret, _, _ := wc.CallG0(sspiTable.EncryptMessage,
			uintptr(unsafe.Pointer(&client.ContextHandle)),
			0,
			uintptr(unsafe.Pointer(desc)),
			0)
		if int32(ret) != 0 {
			return fmt.Errorf("EncryptMessage failed: 0x%x", ret)
		}

		sendLen := int(secBufs[0].CbBuffer + secBufs[1].CbBuffer + secBufs[2].CbBuffer)
		if err := sock.Send(buf[:sendLen]); err != nil {
			return err
		}
		offset += fragLen
		runtime.KeepAlive(secBufs)
		runtime.KeepAlive(desc)
		runtime.KeepAlive(buf)
	}
	return nil
}

func tlsRecv(client *TLSClient, sock *afdSocket) ([]byte, error) {
	var networkBuf []byte
	var response []byte
	recvBuf := make([]byte, 8192)

	headersFound := false
	isChunked := false
	contentLenKnown := false
	var totalExpected int

	for {
		n, err := sock.Recv(recvBuf)
		if err != nil && n == 0 {
			break
		}
		if n > 0 {
			networkBuf = append(networkBuf, recvBuf[:n]...)
		}

		for len(networkBuf) > 0 {
			secBufs := new([4]SecBuffer)
			secBufs[0] = SecBuffer{CbBuffer: uint32(len(networkBuf)), BufferType: SECBUFFER_DATA, PvBuffer: uintptr(unsafe.Pointer(&networkBuf[0]))}
			secBufs[1] = SecBuffer{BufferType: SECBUFFER_EMPTY}
			secBufs[2] = SecBuffer{BufferType: SECBUFFER_EMPTY}
			secBufs[3] = SecBuffer{BufferType: SECBUFFER_EMPTY}
			desc := &SecBufferDesc{UlVersion: SECBUFFER_VERSION, CBuffers: 4, PBuffers: &secBufs[0]}

			ret, _, _ := wc.CallG0(sspiTable.DecryptMessage,
				uintptr(unsafe.Pointer(&client.ContextHandle)),
				uintptr(unsafe.Pointer(desc)),
				0, 0)
			ss := int32(ret)

			if ss == SEC_E_INCOMPLETE_MESSAGE {
				break
			}
			if ret == uintptr(uint32(SEC_I_CONTEXT_EXPIRED)) {
				return response, nil
			}
			if ss != SEC_E_OK && ret != uintptr(uint32(SEC_I_RENEGOTIATE)) {
				return response, fmt.Errorf("DecryptMessage failed: 0x%x", ret)
			}

			for i := 0; i < 4; i++ {
				if secBufs[i].BufferType == SECBUFFER_DATA && secBufs[i].CbBuffer > 0 {
					decrypted := unsafe.Slice((*byte)(unsafe.Pointer(secBufs[i].PvBuffer)), secBufs[i].CbBuffer)
					response = append(response, decrypted...)
				}
			}

			if !headersFound {
				if idx := findHeaderEnd(response); idx >= 0 {
					headersFound = true
					headerPart := response[:idx]
					isChunked = isChunkedResponse(headerPart)
					cl := parseContentLength(headerPart)
					if cl >= 0 {
						contentLenKnown = true
						totalExpected = idx + 4 + cl
					}
				}
			}

			if headersFound {
				if contentLenKnown && len(response) >= totalExpected {
					return response, nil
				}
				if isChunked && hasChunkedTerminator(response) {
					return response, nil
				}
			}

			if ret == uintptr(uint32(SEC_I_RENEGOTIATE)) {
				return response, errors.New("tls renegotiation not supported")
			}

			var extraBuf []byte
			for i := 0; i < 4; i++ {
				if secBufs[i].BufferType == SECBUFFER_EXTRA && secBufs[i].CbBuffer > 0 {
					extraBuf = make([]byte, secBufs[i].CbBuffer)
					copy(extraBuf, unsafe.Slice((*byte)(unsafe.Pointer(secBufs[i].PvBuffer)), secBufs[i].CbBuffer))
					break
				}
			}
			networkBuf = extraBuf

			runtime.KeepAlive(secBufs)
			runtime.KeepAlive(desc)
		}

		if n == 0 {
			break
		}
	}
	return response, nil
}

func tlsRecvRaw(client *TLSClient, sock *afdSocket) ([]byte, error) {
	var networkBuf []byte
	var response []byte
	recvBuf := make([]byte, 8192)

	for {
		n, err := sock.Recv(recvBuf)
		if err != nil && n == 0 {
			if len(response) > 0 {
				return response, nil
			}
			return nil, fmt.Errorf("tls recv: %w", err)
		}
		if n > 0 {
			networkBuf = append(networkBuf, recvBuf[:n]...)
		}

		for len(networkBuf) > 0 {
			secBufs := new([4]SecBuffer)
			secBufs[0] = SecBuffer{CbBuffer: uint32(len(networkBuf)), BufferType: SECBUFFER_DATA, PvBuffer: uintptr(unsafe.Pointer(&networkBuf[0]))}
			secBufs[1] = SecBuffer{BufferType: SECBUFFER_EMPTY}
			secBufs[2] = SecBuffer{BufferType: SECBUFFER_EMPTY}
			secBufs[3] = SecBuffer{BufferType: SECBUFFER_EMPTY}
			desc := &SecBufferDesc{UlVersion: SECBUFFER_VERSION, CBuffers: 4, PBuffers: &secBufs[0]}

			ret, _, _ := wc.CallG0(sspiTable.DecryptMessage,
				uintptr(unsafe.Pointer(&client.ContextHandle)),
				uintptr(unsafe.Pointer(desc)),
				0, 0)
			ss := int32(ret)

			if ss == SEC_E_INCOMPLETE_MESSAGE {
				break
			}
			if ret == uintptr(uint32(SEC_I_CONTEXT_EXPIRED)) {
				return response, nil
			}
			if ss != SEC_E_OK && ret != uintptr(uint32(SEC_I_RENEGOTIATE)) {
				if len(response) > 0 {
					return response, nil
				}
				return nil, fmt.Errorf("DecryptMessage failed: 0x%x", ret)
			}

			for i := 0; i < 4; i++ {
				if secBufs[i].BufferType == SECBUFFER_DATA && secBufs[i].CbBuffer > 0 {
					decrypted := unsafe.Slice((*byte)(unsafe.Pointer(secBufs[i].PvBuffer)), secBufs[i].CbBuffer)
					response = append(response, decrypted...)
				}
			}

			if ret == uintptr(uint32(SEC_I_RENEGOTIATE)) {
				if len(response) > 0 {
					return response, nil
				}
				return nil, errors.New("tls renegotiation not supported")
			}

			var extraBuf []byte
			for i := 0; i < 4; i++ {
				if secBufs[i].BufferType == SECBUFFER_EXTRA && secBufs[i].CbBuffer > 0 {
					extraBuf = make([]byte, secBufs[i].CbBuffer)
					copy(extraBuf, unsafe.Slice((*byte)(unsafe.Pointer(secBufs[i].PvBuffer)), secBufs[i].CbBuffer))
					break
				}
			}
			networkBuf = extraBuf

			runtime.KeepAlive(secBufs)
			runtime.KeepAlive(desc)
		}

		if len(response) > 0 {
			return response, nil
		}

		if n == 0 {
			break
		}
	}
	return response, nil
}

func isChunkedResponse(header []byte) bool {
	s := strings.ToLower(string(header))
	return strings.Contains(s, "transfer-encoding:") && strings.Contains(s, "chunked")
}

func hasChunkedTerminator(data []byte) bool {
	if len(data) < 7 {
		return false
	}
	for i := len(data) - 7; i >= 0; i-- {
		if data[i] == '\r' && i+6 < len(data) {
			if data[i] == '\r' && data[i+1] == '\n' &&
				data[i+2] == '0' &&
				data[i+3] == '\r' && data[i+4] == '\n' &&
				data[i+5] == '\r' && data[i+6] == '\n' {
				return true
			}
		}
	}
	for i := len(data) - 5; i >= 0; i-- {
		if data[i] == '0' && i+4 < len(data) {
			if data[i+1] == '\r' && data[i+2] == '\n' &&
				data[i+3] == '\r' && data[i+4] == '\n' {
				return true
			}
		}
	}
	return false
}

func findHeaderEnd(data []byte) int {
	for i := 0; i+3 < len(data); i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return i
		}
	}
	return -1
}

func parseContentLength(header []byte) int {
	lines := strings.Split(string(header), "\r\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "content-length:") {
			val := strings.TrimSpace(line[len("content-length:"):])
			n := 0
			for _, c := range val {
				if c < '0' || c > '9' {
					return -1
				}
				n = n*10 + int(c-'0')
			}
			return n
		}
	}
	return -1
}

func parseHTTPStatusCode(header []byte) int {
	s := string(header)
	if len(s) < 12 {
		return -1
	}
	spIdx := strings.IndexByte(s, ' ')
	if spIdx < 0 || spIdx+4 > len(s) {
		return -1
	}
	code := 0
	for i := spIdx + 1; i < spIdx+4; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return -1
		}
		code = code*10 + int(c-'0')
	}
	return code
}

func parseLocationHeader(header []byte) string {
	lines := strings.Split(string(header), "\r\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "location:") {
			return strings.TrimSpace(line[len("location:"):])
		}
	}
	return ""
}

func parseURL(rawURL string) (host string, port uint16, path string, err error) {
	if strings.HasPrefix(rawURL, "https://") {
		remaining := rawURL[8:]
		var hostPort string
		if idx := strings.IndexByte(remaining, '/'); idx == -1 {
			hostPort = remaining
			path = "/"
		} else {
			hostPort = remaining[:idx]
			path = remaining[idx:]
		}
		if colonIdx := strings.LastIndexByte(hostPort, ':'); colonIdx != -1 {
			host = hostPort[:colonIdx]
			portStr := hostPort[colonIdx+1:]
			p := 0
			for _, c := range portStr {
				if c < '0' || c > '9' {
					return "", 0, "", fmt.Errorf("invalid port in URL: %s", rawURL)
				}
				p = p*10 + int(c-'0')
			}
			if p <= 0 || p > 65535 {
				return "", 0, "", fmt.Errorf("invalid port number: %d", p)
			}
			port = uint16(p)
		} else {
			host = hostPort
			port = 443
		}
		return host, port, path, nil
	}
	if strings.HasPrefix(rawURL, "http://") {
		return "", 0, "", fmt.Errorf("http:// not supported, only https://")
	}
	return "", 0, "", fmt.Errorf("invalid URL scheme: %s", rawURL)
}

func buildHTTPGetRequest(host, path string) []byte {
	return []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, host))
}

func httpsGet(host string, port uint16, path string) ([]byte, error) {
	ip, err := dnsResolve(host)
	if err != nil {
		return nil, fmt.Errorf("dns resolve %q: %w", host, err)
	}
	sock, err := afdCreateTCPSocket()
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	defer sock.Close()

	if err := sock.Bind(); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	if err := sock.Connect(ip, port); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	var tlsClient TLSClient
	defer tlsFreeClient(&tlsClient)

	if err := tlsAcquireCredentials(&tlsClient); err != nil {
		return nil, err
	}

	hostW, _ := wc.UTF16ptr(host)
	if err := tlsHandshake(&tlsClient, sock, hostW); err != nil {
		return nil, err
	}

	httpReq := buildHTTPGetRequest(host, path)
	if err := tlsSend(&tlsClient, sock, httpReq); err != nil {
		return nil, fmt.Errorf("tls send: %w", err)
	}

	rawResp, err := tlsRecv(&tlsClient, sock)
	runtime.KeepAlive(hostW)
	runtime.KeepAlive(httpReq)
	if err != nil && len(rawResp) == 0 {
		return nil, fmt.Errorf("tls recv: %w", err)
	}
	return rawResp, nil
}

func DownloadToMemory(url string) ([]byte, error) {
	if err := initSSPI(); err != nil {
		return nil, fmt.Errorf("sspi init: %w", err)
	}
	if err := initCrypt32(); err != nil {
		return nil, fmt.Errorf("crypt32 init: %w", err)
	}

	const maxRedirects = 10
	currentURL := url

	for attempt := 0; attempt <= maxRedirects; attempt++ {
		host, port, path, err := parseURL(currentURL)
		if err != nil {
			return nil, err
		}
		rawResp, err := httpsGet(host, port, path)
		if err != nil {
			return nil, err
		}

		headerEnd := findHeaderEnd(rawResp)
		if headerEnd < 0 {
			if len(rawResp) == 0 {
				return nil, errors.New("no data received")
			}
			return rawResp, nil
		}

		headerBytes := rawResp[:headerEnd]
		statusCode := parseHTTPStatusCode(headerBytes)

		if statusCode >= 301 && statusCode <= 308 {
			location := parseLocationHeader(headerBytes)
			if location == "" {
				return nil, fmt.Errorf("HTTP %d redirect with no Location header", statusCode)
			}
			if strings.HasPrefix(location, "/") {
				if port != 443 {
					location = fmt.Sprintf("https://%s:%d%s", host, port, location)
				} else {
					location = "https://" + host + location
				}
			}
			currentURL = location
			continue
		}

		if statusCode < 200 || statusCode >= 300 {
			return nil, fmt.Errorf("HTTP %d", statusCode)
		}

		body := rawResp[headerEnd+4:]
		if len(body) == 0 {
			return nil, errors.New("no body in HTTP response")
		}

		headerStr := string(headerBytes)
		var te, ce string
		for _, line := range strings.Split(headerStr, "\r\n") {
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "transfer-encoding:") {
				te = strings.TrimSpace(line[len("transfer-encoding:"):])
			}
			if strings.HasPrefix(lower, "content-encoding:") {
				ce = strings.TrimSpace(line[len("content-encoding:"):])
			}
		}
		body = decodeBody(body, te, ce)

		return body, nil
	}

	return nil, errors.New("too many redirects")
}
