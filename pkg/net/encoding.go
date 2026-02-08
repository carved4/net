package net

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"
)

func decodeChunked(data []byte) ([]byte, error) {
	var result []byte
	pos := 0
	for pos < len(data) {
		lineEnd := bytes.Index(data[pos:], []byte("\r\n"))
		if lineEnd == -1 {
			break
		}
		chunkSizeStr := string(data[pos : pos+lineEnd])
		if idx := strings.IndexByte(chunkSizeStr, ';'); idx != -1 {
			chunkSizeStr = chunkSizeStr[:idx]
		}
		chunkSizeStr = strings.TrimSpace(chunkSizeStr)
		chunkSize := 0
		for _, c := range chunkSizeStr {
			chunkSize <<= 4
			if c >= '0' && c <= '9' {
				chunkSize |= int(c - '0')
			} else if c >= 'a' && c <= 'f' {
				chunkSize |= int(c - 'a' + 10)
			} else if c >= 'A' && c <= 'F' {
				chunkSize |= int(c - 'A' + 10)
			}
		}
		pos += lineEnd + 2
		if chunkSize == 0 {
			break
		}
		if pos+chunkSize > len(data) {
			result = append(result, data[pos:]...)
			break
		}
		result = append(result, data[pos:pos+chunkSize]...)
		pos += chunkSize
		if pos+2 <= len(data) && data[pos] == '\r' && data[pos+1] == '\n' {
			pos += 2
		}
	}
	return result, nil
}

func decodeGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data, err
	}
	defer reader.Close()
	result, err := io.ReadAll(reader)
	if err != nil {
		return data, err
	}
	return result, nil
}

func decodeDeflate(data []byte) ([]byte, error) {
	if len(data) >= 2 && data[0] == 0x78 {
		zlibReader, err := zlib.NewReader(bytes.NewReader(data))
		if err == nil {
			result, err := io.ReadAll(zlibReader)
			zlibReader.Close()
			if err == nil && len(result) > 0 {
				return result, nil
			}
		}
	}
	reader := flate.NewReader(bytes.NewReader(data))
	result, err := io.ReadAll(reader)
	reader.Close()
	if err == nil && len(result) > 0 {
		return result, nil
	}
	return data, err
}

func decodeBody(body []byte, transferEncoding, contentEncoding string) []byte {
	result := body
	te := strings.ToLower(transferEncoding)
	if strings.Contains(te, "chunked") {
		decoded, err := decodeChunked(result)
		if err == nil {
			result = decoded
		}
	}
	ce := strings.ToLower(contentEncoding)
	if strings.Contains(ce, "gzip") {
		decoded, err := decodeGzip(result)
		if err == nil {
			result = decoded
		}
	} else if strings.Contains(ce, "deflate") {
		decoded, err := decodeDeflate(result)
		if err == nil {
			result = decoded
		}
	}
	return result
}

