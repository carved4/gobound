/*
net.go is a standalone, reusable downloader package using pure winhttp, it only accepts valid https urls with
valid certs, if the cert is invalid it will fail, the downloaded data is placed into a buffer that can be used for whatever
*/

package net

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/carved4/go-wincall"
)

func Download(url string) ([]byte, error) {
	if len(url) < 8 {
		return nil, fmt.Errorf("invalid URL")
	}

	var host, path string

	if url[:8] == "https://" {
		remaining := url[8:]
		slashPos := -1
		for i, c := range remaining {
			if c == '/' {
				slashPos = i
				break
			}
		}
		if slashPos == -1 {
			host = remaining
			path = "/"
		} else {
			host = remaining[:slashPos]
			path = remaining[slashPos:]
		}
	} else {
		return nil, fmt.Errorf("only HTTPS supported")
	}
	wincall.LoadLibraryW("winhttp.dll")
	dllHash := wincall.GetHash("winhttp.dll")
	moduleBase := wincall.GetModuleBase(dllHash)
	winHttpOpenHash := wincall.GetHash("WinHttpOpen")
	winHttpOpenAddr := wincall.GetFunctionAddress(moduleBase, winHttpOpenHash)
	winHttpConnectHash := wincall.GetHash("WinHttpConnect")
	winHttpConnectAddr := wincall.GetFunctionAddress(moduleBase, winHttpConnectHash)
	winHttpOpenRequestHash := wincall.GetHash("WinHttpOpenRequest")
	winHttpOpenRequestAddr := wincall.GetFunctionAddress(moduleBase, winHttpOpenRequestHash)
	winHttpSendRequestHash := wincall.GetHash("WinHttpSendRequest")
	winHttpSendRequestAddr := wincall.GetFunctionAddress(moduleBase, winHttpSendRequestHash)
	winHttpReceiveResponseHash := wincall.GetHash("WinHttpReceiveResponse")
	winHttpReceiveResponseAddr := wincall.GetFunctionAddress(moduleBase, winHttpReceiveResponseHash)
	winHttpReadDataHash := wincall.GetHash("WinHttpReadData")
	winHttpReadDataAddr := wincall.GetFunctionAddress(moduleBase, winHttpReadDataHash)
	winHttpCloseHandleHash := wincall.GetHash("WinHttpCloseHandle")
	winHttpCloseHandleAddr := wincall.GetFunctionAddress(moduleBase, winHttpCloseHandleHash)
	// if you see me and you cloned this change me
	userAgent, _ := wincall.UTF16ptr("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	hostUTF16, _ := wincall.UTF16ptr(host)
	pathUTF16, _ := wincall.UTF16ptr(path)
	getUTF16, _ := wincall.UTF16ptr("GET")
	hSession, _, _ := wincall.CallG0(winHttpOpenAddr, userAgent, 0, 0, 0, 0)
	if hSession == 0 {
		return nil, fmt.Errorf("WinHttpOpen failed")
	}
	defer wincall.CallG0(winHttpCloseHandleAddr, hSession)
	hConnect, _, _ := wincall.CallG0(winHttpConnectAddr, hSession, hostUTF16, uintptr(443), 0)
	if hConnect == 0 {
		return nil, fmt.Errorf("WinHttpConnect failed")
	}
	defer wincall.CallG0(winHttpCloseHandleAddr, hConnect)
	hRequest, _, _ := wincall.CallG0(winHttpOpenRequestAddr, hConnect, getUTF16, pathUTF16, 0, 0, 0, 0x00800000) // WINHTTP_FLAG_SECURE
	if hRequest == 0 {
		return nil, fmt.Errorf("WinHttpOpenRequest failed")
	}
	defer wincall.CallG0(winHttpCloseHandleAddr, hRequest)
	result, _, _ := wincall.CallG0(winHttpSendRequestAddr, hRequest, 0, 0, 0, 0, 0, 0)
	if result == 0 {
		return nil, fmt.Errorf("WinHttpSendRequest failed")
	}
	result, _, _ = wincall.CallG0(winHttpReceiveResponseAddr, hRequest, 0)
	if result == 0 {
		return nil, fmt.Errorf("WinHttpReceiveResponse failed")
	}
	var buffer []byte
	chunk := make([]byte, 4096)
	for {
		var bytesRead uint32
		bytesReadPtr := uintptr(unsafe.Pointer(&bytesRead))
		chunkPtr := uintptr(unsafe.Pointer(&chunk[0]))

		result, _, _ := wincall.CallG0(winHttpReadDataAddr, hRequest, chunkPtr, uintptr(len(chunk)), bytesReadPtr)
		if result == 0 {
			return nil, fmt.Errorf("WinHttpReadData failed")
		}
		if bytesRead == 0 {
			break
		}
		buffer = append(buffer, chunk[:bytesRead]...)
	}
	runtime.KeepAlive(userAgent)
	runtime.KeepAlive(hostUTF16)
	runtime.KeepAlive(pathUTF16)
	runtime.KeepAlive(getUTF16)
	runtime.KeepAlive(chunk)
	if len(buffer) == 0 {
		return nil, fmt.Errorf("no data downloaded")
	}
	return buffer, nil
}
