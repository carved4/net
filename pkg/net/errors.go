package net

type NetErrorType int

const (
	ErrNone NetErrorType = iota
	ErrDNSResolution
	ErrConnection
	ErrConnectionRefused
	ErrConnectionTimeout
	ErrTLSHandshake
	ErrTLSCertificate
	ErrHTTPStatus
	ErrHTTPRedirect
	ErrHTTPParse
	ErrSocketCreate
	ErrSocketBind
	ErrSocketSend
	ErrSocketRecv
	ErrSSPIInit
	ErrCrypt32Init
)

type NetError struct {
	Type    NetErrorType
	Message string
	Code    int
	Inner   error
}

func (e *NetError) Error() string {
	if e.Inner != nil {
		return e.Message + ": " + e.Inner.Error()
	}
	return e.Message
}

func (e *NetError) Unwrap() error {
	return e.Inner
}

func newNetError(t NetErrorType, msg string, inner error) *NetError {
	return &NetError{Type: t, Message: msg, Inner: inner}
}

func newNetErrorCode(t NetErrorType, msg string, code int) *NetError {
	return &NetError{Type: t, Message: msg, Code: code}
}

