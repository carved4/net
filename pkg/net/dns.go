package net

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

var (
	dnsQueryW uintptr
	dnsFree   uintptr
)

func initDnsApi() error {
	if dnsQueryW != 0 {
		return nil
	}
	wc.LoadLibraryLdr("dnsapi.dll")
	base := wc.GetModuleBase(wc.GetHash("dnsapi.dll"))
	if base == 0 {
		return errors.New("failed to load dnsapi.dll")
	}
	dnsQueryW = wc.GetFunctionAddress(base, wc.GetHash("DnsQuery_W"))
	dnsFree = wc.GetFunctionAddress(base, wc.GetHash("DnsFree"))
	if dnsQueryW == 0 || dnsFree == 0 {
		return errors.New("failed to resolve dnsapi functions")
	}
	return nil
}

func dnsResolve(hostname string) (uint32, error) {
	if err := initDnsApi(); err != nil {
		return 0, err
	}

	hostnameW, _ := wc.UTF16ptr(hostname)
	var results uintptr

	ret, _, _ := wc.CallG0(dnsQueryW,
		uintptr(unsafe.Pointer(hostnameW)),
		uintptr(1),
		uintptr(0),
		0,
		uintptr(unsafe.Pointer(&results)),
		0)

	if ret != 0 {
		return 0, fmt.Errorf("DnsQuery_W failed: 0x%x", ret)
	}
	defer wc.CallG0(dnsFree, results, 0)

	if results == 0 {
		return 0, errors.New("dns: no records returned")
	}

	ipAddr := *(*uint32)(unsafe.Pointer(results + 32))

	runtime.KeepAlive(hostnameW)
	return ipAddr, nil
}

func dnsResolveAll(hostname string) ([]uint32, error) {
	if err := initDnsApi(); err != nil {
		return nil, err
	}

	hostnameW, _ := wc.UTF16ptr(hostname)
	var results uintptr

	ret, _, _ := wc.CallG0(dnsQueryW,
		uintptr(unsafe.Pointer(hostnameW)),
		uintptr(1),
		uintptr(0),
		0,
		uintptr(unsafe.Pointer(&results)),
		0)

	if ret != 0 {
		return nil, fmt.Errorf("DnsQuery_W failed: 0x%x", ret)
	}
	defer wc.CallG0(dnsFree, results, 0)

	if results == 0 {
		return nil, errors.New("dns: no records returned")
	}

	var ips []uint32
	current := results
	for current != 0 {
		recType := *(*uint16)(unsafe.Pointer(current + 16))
		if recType == 1 {
			ipAddr := *(*uint32)(unsafe.Pointer(current + 32))
			ips = append(ips, ipAddr)
		}
		current = *(*uintptr)(unsafe.Pointer(current))
	}

	runtime.KeepAlive(hostnameW)
	if len(ips) == 0 {
		return nil, errors.New("dns: no A records found")
	}
	return ips, nil
}

type DNSResolver struct {
	useSystemDNS bool
}

func NewDNSResolver() *DNSResolver {
	return &DNSResolver{useSystemDNS: true}
}

func (r *DNSResolver) Resolve(hostname string) (uint32, error) {
	return dnsResolve(hostname)
}

func (r *DNSResolver) ResolveAll(hostname string) ([]uint32, error) {
	return dnsResolveAll(hostname)
}
