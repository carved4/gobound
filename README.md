# gobound

remote dll injection into chrome to extract cookies and passwords via the chrome elevator com interface.
this works for V20 cookies/passwords (app bound encryption), for prior versions just call cryptunprotect as curr user

## what it does

1. finds a running chrome process
2. downloads a payload dll from a remote url
3. injects the dll into chrome using manual pe mapping (no loadlibrary)
4. the dll uses chrome's elevation service to decrypt the master key
5. extracts cookies, passwords, and saved cards from all chrome profiles
6. sends data back via named pipe
7. saves everything to `chrome_data.json`

## building

### injector (cmd/)

```
cd cmd
go build -o gobound.exe
```

### payload dll (dll/main/)

```
cd dll/main
go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o payload.dll
```

## usage (if you don't want to add functionality to dll/main/main.go)

1. build the injector `go build -o gobound.exe cmd/main.go' 
2. run `gobound.exe` while chrome is running

## usage (if you want to change the src of dll payload)

1. recompile dll with `go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o payload.dll dll/main/main.go`
2. host it at an https endpoint
3. update the download url in `cmd/main.go`
4. build the injector `go build -o gobound.exe cmd/main.go`
5. run `gobound.exe` while chrome is running

## output

`chrome_data.json` contains:
- master key (base64)
- cookies (profile, host, name, value)
- passwords (profile, url, username, password)
- cards (profile, name on card, expiration, number)

## dependencies

- github.com/carved4/go-wincall - syscalls and win32 api
- modernc.org/sqlite - pure go sqlite for reading chrome dbs
