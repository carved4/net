package net

import (
	"sync"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

const (
	KEY_READ              = 0x20019
	REG_SZ                = 1
	STATUS_SUCCESS        = 0
	STATUS_BUFFER_TOO_SMALL = 0x80000005
)

var (
	cachedUA     string
	cachedUAOnce sync.Once
)

type TLSConfig struct {
	SkipVerify bool
	ServerName string
}

type HTTPConfig struct {
	Headers      map[string]string
	UserAgent    string
	KeepAlive    bool
	MaxRedirects int
}

type ClientConfig struct {
	TLS  TLSConfig
	HTTP HTTPConfig
}

func getSystemUserAgent() string {
	cachedUAOnce.Do(func() {
		cachedUA = readRegistryUA()
	})
	return cachedUA
}

func readRegistryUA() string {
	ntdll := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	if ntdll == 0 {
		return ""
	}

	ntOpenKey := wc.GetFunctionAddress(ntdll, wc.GetHash("NtOpenKey"))
	ntQueryValueKey := wc.GetFunctionAddress(ntdll, wc.GetHash("NtQueryValueKey"))
	ntClose := wc.GetFunctionAddress(ntdll, wc.GetHash("NtClose"))
	if ntOpenKey == 0 || ntQueryValueKey == 0 || ntClose == 0 {
		return ""
	}

	keyPath := `\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`
	keyPathW, _ := wc.UTF16ptr(keyPath)

	var objectAttrs struct {
		Length                   uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}

	var unicodeStr struct {
		Length        uint16
		MaximumLength uint16
		Buffer        uintptr
	}

	pathLen := 0
	for p := keyPathW; *p != 0; p = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 2)) {
		pathLen++
	}
	unicodeStr.Length = uint16(pathLen * 2)
	unicodeStr.MaximumLength = uint16(pathLen*2 + 2)
	unicodeStr.Buffer = uintptr(unsafe.Pointer(keyPathW))

	objectAttrs.Length = uint32(unsafe.Sizeof(objectAttrs))
	objectAttrs.ObjectName = uintptr(unsafe.Pointer(&unicodeStr))
	objectAttrs.Attributes = 0x40

	var keyHandle uintptr
	ret, _, _ := wc.CallG0(ntOpenKey,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(KEY_READ),
		uintptr(unsafe.Pointer(&objectAttrs)))

	if ret != STATUS_SUCCESS {
		return ""
	}
	defer wc.CallG0(ntClose, keyHandle)

	valueName := "User Agent"
	valueNameW, _ := wc.UTF16ptr(valueName)

	var valueUnicodeStr struct {
		Length        uint16
		MaximumLength uint16
		Buffer        uintptr
	}

	valueLen := 0
	for p := valueNameW; *p != 0; p = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 2)) {
		valueLen++
	}
	valueUnicodeStr.Length = uint16(valueLen * 2)
	valueUnicodeStr.MaximumLength = uint16(valueLen*2 + 2)
	valueUnicodeStr.Buffer = uintptr(unsafe.Pointer(valueNameW))

	var resultLen uint32
	ret, _, _ = wc.CallG0(ntQueryValueKey,
		keyHandle,
		uintptr(unsafe.Pointer(&valueUnicodeStr)),
		uintptr(2),
		0,
		uintptr(0),
		uintptr(unsafe.Pointer(&resultLen)))

	if resultLen == 0 || resultLen > 4096 {
		return ""
	}

	buf := make([]byte, resultLen)
	ret, _, _ = wc.CallG0(ntQueryValueKey,
		keyHandle,
		uintptr(unsafe.Pointer(&valueUnicodeStr)),
		uintptr(2),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(resultLen),
		uintptr(unsafe.Pointer(&resultLen)))

	if ret != STATUS_SUCCESS {
		return ""
	}

	if resultLen < 16 {
		return ""
	}

	dataOffset := *(*uint32)(unsafe.Pointer(&buf[8]))
	dataLen := *(*uint32)(unsafe.Pointer(&buf[12]))

	if dataOffset+dataLen > resultLen || dataLen < 2 {
		return ""
	}

	data := buf[dataOffset : dataOffset+dataLen]
	result := make([]byte, 0, dataLen/2)
	for i := 0; i+1 < len(data); i += 2 {
		c := uint16(data[i]) | uint16(data[i+1])<<8
		if c == 0 {
			break
		}
		if c < 128 {
			result = append(result, byte(c))
		}
	}

	return string(result)
}

func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		TLS: TLSConfig{
			SkipVerify: false,
		},
		HTTP: HTTPConfig{
			Headers:      make(map[string]string),
			UserAgent:    getSystemUserAgent(),
			KeepAlive:    false,
			MaxRedirects: 10,
		},
	}
}

func (c *ClientConfig) WithSkipVerify(skip bool) *ClientConfig {
	c.TLS.SkipVerify = skip
	return c
}

func (c *ClientConfig) WithUserAgent(ua string) *ClientConfig {
	c.HTTP.UserAgent = ua
	return c
}

func (c *ClientConfig) WithHeader(key, value string) *ClientConfig {
	c.HTTP.Headers[key] = value
	return c
}

func (c *ClientConfig) WithHeaders(headers map[string]string) *ClientConfig {
	for k, v := range headers {
		c.HTTP.Headers[k] = v
	}
	return c
}

func (c *ClientConfig) WithKeepAlive(keepAlive bool) *ClientConfig {
	c.HTTP.KeepAlive = keepAlive
	return c
}

func (c *ClientConfig) WithMaxRedirects(max int) *ClientConfig {
	c.HTTP.MaxRedirects = max
	return c
}
