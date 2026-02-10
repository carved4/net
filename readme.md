# net

low-level windows networking library using afd.sys sockets and schannel tls. bypasses winsock, winhttp, wininet and other high-level networking apis entirely.

## features

- **afd.sys sockets** - raw socket i/o via `\Device\Afd` using ntdeviceiocontrolfile
- **schannel/sspi tls** - native windows tls with full certificate validation
- **indirect syscalls** - all nt api calls go through syscall;ret gadgets
- **dns resolution** - uses doh to cloudflare and google to resolve dns
- **dynamic user agent** - reads system ua from registry via ntqueryvaluekey
- **http encoding** - handles chunked transfer, gzip, and deflate
- **redirect following** - automatic 301-308 redirect handling

## install

```bash
go get github.com/carved4/net
```

## usage

### simple download

```go
import "github.com/carved4/net"

// download bytes to memory
data, err := net.Download("https://example.com/file.dll", nil)

// with custom config
data, err := net.Download("https://example.com/file.dll", &net.Config{
    UserAgent: "MyApp/1.0",
    Headers: map[string]string{
        "Authorization": "Bearer token",
    },
})
```

### http get/post

```go
// simple get
body, err := net.Get("https://example.com", nil)

// get with custom headers
body, err := net.Get("https://httpbin.org/get", &net.Config{
    UserAgent: "CustomAgent/1.0",
    Headers: map[string]string{
        "X-Custom-Header": "value",
    },
})

// post data
body, err := net.Post("https://httpbin.org/post", []byte(`{"key":"value"}`), &net.Config{
    Headers: map[string]string{
        "Content-Type": "application/json",
    },
})

// post with io.Reader (uses chunked transfer encoding)
reader := strings.NewReader("streaming data")
body, err := net.PostWithReader("https://httpbin.org/post", 
    map[string]string{"Content-Type": "text/plain"}, 
    reader, nil)
```

### dns resolution

```go
// resolve hostname to ip
ip, err := net.Resolve("example.com")
fmt.Println(net.IPv4String(ip)) // "93.184.216.34"

// get all a records
ips, err := net.ResolveAll("google.com")
```

### low-level tls connection

```go
// dial tls connection
conn, err := net.Dial("example.com", 443, nil)
defer conn.Close()

// send/recv raw data
conn.Send([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
response, err := conn.Recv()
```

### raw tcp connection

```go
// dial raw tcp (no tls)
ip, _ := net.Resolve("example.com")
conn, err := net.DialRawIP(ip, 80)
defer conn.Close()

conn.Send([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
buf := make([]byte, 4096)
n, err := conn.Recv(buf)
```

### streaming http requests

```go
// dial a persistent stream connection
conn, path, err := net.DialStream("https://httpbin.org/post", nil)
defer conn.Close()

// send regular request with body
headers := map[string]string{"Content-Type": "application/json"}
resp, err := conn.SendRequest("POST", path, headers, []byte(`{"key":"value"}`), "MyAgent/1.0")

// send chunked transfer-encoded request
reader := strings.NewReader("large streaming data")
resp, err = conn.SendChunkedRequest("POST", path, headers, reader, "MyAgent/1.0")
```

convenience functions for streaming:

```go
// post with chunked transfer encoding
reader := strings.NewReader("chunked body")
resp, err := net.PostChunked("https://httpbin.org/post", 
    map[string]string{"Content-Type": "text/plain"}, 
    reader, nil)

// post via stream connection (connection: close)
resp, err := net.PostStream("https://httpbin.org/post", 
    map[string]string{"Content-Type": "text/plain"}, 
    []byte("body"), nil)
```

### http client with full control

```go
// create client with custom config
config := net.DefaultConfig().
    WithUserAgent("MyClient/2.0").
    WithHeader("Accept-Language", "en-US").
    WithMaxRedirects(5)

client := net.NewHTTPClient(config)

// make request
resp, err := client.Get("https://httpbin.org/get")
fmt.Println(resp.StatusCode)
fmt.Println(resp.Headers)
fmt.Println(string(resp.Body))

// post with headers
resp, err = client.PostWithHeaders("https://httpbin.org/post", 
    []byte("data"), 
    map[string]string{"Content-Type": "text/plain"})
```

### error handling

```go
body, err := net.Get("https://httpbin.org/status/404", nil)
if err != nil {
    if net.IsNetError(err) {
        switch net.GetNetErrorType(err) {
        case net.ErrHTTPStatus:
            fmt.Printf("http error: %d\n", net.GetNetErrorCode(err))
        case net.ErrDNSResolution:
            fmt.Println("dns failed")
        case net.ErrTLSHandshake:
            fmt.Println("tls failed")
        case net.ErrConnection:
            fmt.Println("connection failed")
        }
    }
}
```

## api reference

### functions

| function | description |
|----------|-------------|
| `Download(url, config)` | download bytes to memory with redirect following |
| `Get(url, config)` | http get request |
| `Post(url, body, config)` | http post request |
| `PostWithReader(url, headers, reader, config)` | post with io.Reader body (chunked transfer) |
| `PostChunked(url, headers, reader, config)` | post with chunked transfer encoding |
| `PostStream(url, headers, body, config)` | post via stream connection |
| `DialStream(url, config)` | dial persistent stream connection for http |
| `Resolve(hostname)` | resolve hostname to ipv4 |
| `ResolveAll(hostname)` | resolve hostname to all ipv4 addresses |
| `Dial(host, port, config)` | dial tls connection |
| `DialRaw(host, port, config)` | dial raw tcp connection |
| `DialRawIP(ip, port)` | dial raw tcp to ip |
| `IPv4(a, b, c, d)` | create uint32 ip from octets |
| `IPv4String(ip)` | convert uint32 ip to string |

### config

```go
type Config struct {
    UserAgent string
    Headers   map[string]string
}
```

### error types

| type | description |
|------|-------------|
| `ErrDNSResolution` | dns lookup failed |
| `ErrConnection` | tcp connect failed |
| `ErrTLSHandshake` | tls handshake failed |
| `ErrHTTPStatus` | non-2xx http status |
| `ErrHTTPRedirect` | too many redirects |
| `ErrSocketCreate` | socket creation failed |
| `ErrSocketBind` | socket bind failed |
| `ErrSocketSend` | send failed |
| `ErrSocketRecv` | recv failed |

## package structure

```
pkg/net/
├── api.go       # public api functions
├── config.go    # client configuration + registry ua extraction
├── conn.go      # tls/raw/udp connection types
├── dns.go       # dnsquery_w resolution
├── encoding.go  # chunked/gzip/deflate decoding
├── errors.go    # typed error definitions
├── http.go      # http client implementation
├── net.go       # afd socket + schannel tls core
├── stream.go    # streaming http connections + chunked transfer
├── udp.go       # udp socket implementation
└── unsafe.go    # unsafe helpers
```

## why not net/http?

this library is designed for scenarios where you need:

- bypass of usermode api hooks (winhttp, wininet, winsock)
- no ie/wininet cache or proxy auto-detection
- minimal api surface for evasion
- direct control over socket operations
- no high-level abstractions

## credits

afd.sys socket code based on work by [@vxunderground](https://x.com/vxunderground)
