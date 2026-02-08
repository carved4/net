package net

import "unsafe"

func unsafePointer[T any](v *T) unsafe.Pointer {
	return unsafe.Pointer(v)
}

func unsafePointerFromUintptr(v uintptr) unsafe.Pointer {
	return unsafe.Pointer(v)
}

func unsafeSlice(ptr *byte, len uint32) []byte {
	return unsafe.Slice(ptr, len)
}

