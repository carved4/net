package net

import "io"

type Config struct {
	UserAgent string
	Headers   map[string]string
}

func Get(url string, config *Config) ([]byte, error) {
	cc := toClientConfig(config)
	client := NewHTTPClient(cc)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func Post(url string, body []byte, config *Config) ([]byte, error) {
	cc := toClientConfig(config)
	client := NewHTTPClient(cc)
	resp, err := client.Post(url, body)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func PostWithReader(url string, headers map[string]string, bodyReader io.Reader, config *Config) ([]byte, error) {
	resp, err := PostChunked(url, headers, bodyReader, config)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func toClientConfig(c *Config) *ClientConfig {
	cc := DefaultConfig()
	if c == nil {
		return cc
	}
	if c.UserAgent != "" {
		cc.HTTP.UserAgent = c.UserAgent
	}
	if c.Headers != nil {
		for k, v := range c.Headers {
			cc.HTTP.Headers[k] = v
		}
	}
	return cc
}

func Resolve(hostname string) (uint32, error) {
	return dnsResolve(hostname)
}

func ResolveAll(hostname string) ([]uint32, error) {
	return dnsResolveAll(hostname)
}

func Download(url string, config *Config) ([]byte, error) {
	if config == nil {
		return DownloadToMemory(url)
	}
	return Get(url, config)
}

func IPv4(a, b, c, d byte) uint32 {
	return uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24
}

func IPv4String(ip uint32) string {
	result := make([]byte, 0, 15)
	for i := 0; i < 4; i++ {
		octet := byte((ip >> (i * 8)) & 0xff)
		if octet >= 100 {
			result = append(result, '0'+octet/100)
		}
		if octet >= 10 {
			result = append(result, '0'+(octet/10)%10)
		}
		result = append(result, '0'+octet%10)
		if i < 3 {
			result = append(result, '.')
		}
	}
	return string(result)
}

func IsNetError(err error) bool {
	_, ok := err.(*NetError)
	return ok
}

func GetNetErrorType(err error) NetErrorType {
	if ne, ok := err.(*NetError); ok {
		return ne.Type
	}
	return ErrNone
}

func GetNetErrorCode(err error) int {
	if ne, ok := err.(*NetError); ok {
		return ne.Code
	}
	return 0
}
