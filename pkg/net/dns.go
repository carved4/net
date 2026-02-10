package net

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

var dohServers = [][2]uint32{
	{0x08080808, 'g'},
	{0x01010101, 'c'},
	{0x04040808, 'g'},
	{0x01000001, 'c'},
}

func dohHost(provider uint32) string {
	if provider == 'g' {
		return "dns.google"
	}
	return "cloudflare-dns.com"
}

type dnsCache struct {
	mu	sync.RWMutex
	entries	map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	ips	[]uint32
	expires	int64
}

var cache = &dnsCache{entries: make(map[string]dnsCacheEntry)}

const dnsCacheTTL = 300

func (c *dnsCache) get(hostname string) ([]uint32, bool) {
	c.mu.RLock()
	entry, ok := c.entries[hostname]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().Unix() > entry.expires {
		c.mu.Lock()
		delete(c.entries, hostname)
		c.mu.Unlock()
		return nil, false
	}
	return entry.ips, true
}

func (c *dnsCache) set(hostname string, ips []uint32) {
	c.mu.Lock()
	c.entries[hostname] = dnsCacheEntry{
		ips:		ips,
		expires:	time.Now().Unix() + dnsCacheTTL,
	}
	c.mu.Unlock()
}

func buildDNSQuery(hostname string) ([]byte, error) {
	if len(hostname) == 0 {
		return nil, errors.New("empty hostname")
	}

	estLen := 12 + len(hostname) + 2 + 4
	query := make([]byte, 0, estLen)

	query = append(query, 0xAB, 0xCD)
	query = append(query, 0x01, 0x00)
	query = append(query, 0x00, 0x01)
	query = append(query, 0x00, 0x00)
	query = append(query, 0x00, 0x00)
	query = append(query, 0x00, 0x00)

	start := 0
	for i := 0; i <= len(hostname); i++ {
		if i == len(hostname) || hostname[i] == '.' {
			labelLen := i - start
			if labelLen == 0 {
				return nil, errors.New("empty label in hostname")
			}
			if labelLen > 63 {
				return nil, errors.New("label too long")
			}
			query = append(query, byte(labelLen))
			query = append(query, hostname[start:i]...)
			start = i + 1
		}
	}
	query = append(query, 0x00)
	query = append(query, 0x00, 0x01)
	query = append(query, 0x00, 0x01)

	return query, nil
}

func parseDNSResponse(data []byte) ([]uint32, error) {
	if len(data) < 12 {
		return nil, errors.New("dns response too short")
	}

	rcode := data[3] & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("dns error: rcode %d", rcode)
	}

	ancount := int(data[6])<<8 | int(data[7])
	if ancount == 0 {
		return nil, errors.New("dns: no answers")
	}

	offset := 12
	for offset < len(data) && data[offset] != 0 {
		if data[offset]&0xC0 == 0xC0 {
			offset += 2
			goto skipQDone
		}
		offset += int(data[offset]) + 1
	}
	offset++
skipQDone:
	offset += 4

	ips := make([]uint32, 0, ancount)
	for i := 0; i < ancount && offset+12 <= len(data); i++ {
		if data[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(data) && data[offset] != 0 {
				offset += int(data[offset]) + 1
			}
			offset++
		}

		if offset+10 > len(data) {
			break
		}

		rtype := int(data[offset])<<8 | int(data[offset+1])
		rdlen := int(data[offset+8])<<8 | int(data[offset+9])
		offset += 10

		if rtype == 1 && rdlen == 4 && offset+4 <= len(data) {
			ip := uint32(data[offset]) | uint32(data[offset+1])<<8 |
				uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
			ips = append(ips, ip)
		}
		offset += rdlen
	}

	if len(ips) == 0 {
		return nil, errors.New("dns: no A records found")
	}
	return ips, nil
}

func dohQueryFast(hostname string, serverHost string, serverIP uint32) ([]uint32, error) {
	dnsQuery, err := buildDNSQuery(hostname)
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(dnsQuery)

	rawResp, err := httpsGetWithIP(serverHost, 443, "/dns-query?dns="+encoded, serverIP)
	if err != nil {
		return nil, err
	}

	headerEnd := findHeaderEnd(rawResp)
	if headerEnd < 0 || headerEnd+4 >= len(rawResp) {
		return nil, errors.New("invalid http response")
	}

	if len(rawResp) > 12 {
		sp := 0
		for sp < headerEnd && rawResp[sp] != ' ' {
			sp++
		}
		if sp+4 <= headerEnd {
			code := (int(rawResp[sp+1])-'0')*100 + (int(rawResp[sp+2])-'0')*10 + int(rawResp[sp+3]) - '0'
			if code < 200 || code >= 300 {
				return nil, fmt.Errorf("doh http error: %d", code)
			}
		}
	}

	body := rawResp[headerEnd+4:]
	return parseDNSResponse(body)
}

type dohResult struct {
	ips	[]uint32
	err	error
}

func dnsResolveParallel(hostname string) ([]uint32, error) {
	if err := initSSPI(); err != nil {
		return nil, err
	}
	if err := initCrypt32(); err != nil {
		return nil, err
	}

	if ips, ok := cache.get(hostname); ok {
		return ips, nil
	}

	resultCh := make(chan dohResult, len(dohServers))

	for _, server := range dohServers {
		go func(ip, provider uint32) {
			ips, err := dohQueryFast(hostname, dohHost(provider), ip)
			select {
			case resultCh <- dohResult{ips, err}:
			default:
			}
		}(server[0], server[1])
	}

	timeout := time.After(10 * time.Second)
	var lastErr error
	received := 0

	for received < len(dohServers) {
		select {
		case result := <-resultCh:
			received++
			if result.err == nil && len(result.ips) > 0 {
				cache.set(hostname, result.ips)
				return result.ips, nil
			}
			if result.err != nil {
				lastErr = result.err
			}
		case <-timeout:
			if lastErr != nil {
				return nil, fmt.Errorf("dns timeout: %w", lastErr)
			}
			return nil, errors.New("dns resolution timeout")
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all doh servers failed: %w", lastErr)
	}
	return nil, errors.New("dns resolution failed")
}

func dnsResolve(hostname string) (uint32, error) {
	ips, err := dnsResolveParallel(hostname)
	if err != nil {
		return 0, err
	}
	return ips[0], nil
}

func dnsResolveAll(hostname string) ([]uint32, error) {
	return dnsResolveParallel(hostname)
}

type DNSResolver struct{}

func NewDNSResolver() *DNSResolver {
	return &DNSResolver{}
}

func (r *DNSResolver) Resolve(hostname string) (uint32, error) {
	return dnsResolve(hostname)
}

func (r *DNSResolver) ResolveAll(hostname string) ([]uint32, error) {
	return dnsResolveAll(hostname)
}

