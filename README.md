# gobound

remote dll injection into chrome to extract cookies and passwords via the chrome elevator com interface.
this works for v20 cookies/passwords (app bound encryption), for prior versions just call cryptunprotect as curr user

## what it does

1. scans all chrome.exe processes for open handles to database files (cookies, login data, web data)
2. identifies which chrome process owns the database handles
3. duplicates the handles and extracts locked database files to temp directory
4. downloads the payload dll
5. injects the dll into the chrome process that owns the database handles using manual pe mapping
6. sends temp file paths to the injected dll via named pipe
7. the dll uses chrome's elevation service to decrypt the master key
8. the dll reads from the extracted temp files and decrypts cookies, passwords, and saved cards
9. sends decrypted data back via named pipe
10. cleans up temp files and saves everything to `chrome_data.json`

## technical details

### handle hijacking
- uses `ntquerysysteminformation` to enumerate all chrome processes and their handles
- iterates through handles with 100ms timeout per handle to avoid hanging on pipes/blocking handles
- extracts file path from each handle using `ntqueryinformationfile`
- duplicates target handles with `ntduplicateobject` to read locked database files
- early exits once all three target files are found (cookies, login data, web data)

### extraction flow
- duplicated handles allow reading sqlite databases that are locked by chrome
- files are extracted to `os.tempdir()` with naming scheme: `chrome_{dbtype}_{pid}.db`
- injector sends temp file paths to dll via named pipe using `TEMPFILE:` protocol
- dll performs sqlite queries directly on temp files instead of trying to access locked files

### encryption handling
- uses chrome's `ichromeupdate` elevation service com interface to decrypt app-bound master key
- master key is used to decrypt aes-gcm encrypted v20 values
- supports extraction from all chrome profiles (default, profile 1, profile 2, etc)

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

1. build the injector `go build -o gobound.exe cmd/main.go` 
2. run `gobound.exe` while chrome is running

## usage (if you want to change the src of dll payload)

1. recompile dll with `go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o payload.dll dll/main/main.go`
2. host it at an https endpoint
3. update the download url in `cmd/main.go`
4. build the injector `go build -o gobound.exe cmd/main.go`
5. run `gobound.exe` while chrome is running

## output

`chrome_data.json` contains:
- master key (hex)
- cookies (profile, host, name, value)
- passwords (profile, url, username, password)
- cards (profile, name on card, expiration, number)

## dependencies

- github.com/carved4/go-wincall - syscalls and win32 api
- modernc.org/sqlite - pure go sqlite for reading chrome dbs
