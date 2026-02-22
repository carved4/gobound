# gobound

remote dll injection into chrome to extract cookies and passwords via the chrome elevator com interface.
this works for v20 cookies/passwords (app bound encryption), for prior versions just call cryptunprotect as curr user

## what it does

1. scans all chrome.exe processes for open handles to database files (cookies, login data, web data)
2. identifies which chrome process owns the database handles
3. duplicates the handles and extracts locked database files directly into memory
4. downloads the payload dll from https endpoint
5. injects the dll into the chrome process that owns the database handles using manual pe mapping
6. the dll uses chrome's elevation service to decrypt the master key
7. the dll sends the decrypted master key back to the injector via named pipe
8. injector decrypts all data in-memory using the master key
9. saves everything to `chrome_data.json` (no temp files created)

## technical details

### handle hijacking
- uses `ntquerysysteminformation` to enumerate all chrome processes and their handles
- iterates through handles with 100ms timeout per handle to avoid hanging on pipes/blocking handles
- extracts file path from each handle using `ntqueryinformationfile`
- duplicates target handles with `ntduplicateobject` to read locked database files
- early exits once all three target files are found (cookies, login data, web data)

### extraction flow
- duplicated handles allow reading sqlite databases that are locked by chrome
- database contents are read directly into memory (no temp files)
- sqlite parsing uses in-memory deserialization via `zombiezen.com/go/sqlite`
- injector performs all sqlite queries and decryption locally after receiving the master key
- all database processing happens in the injector, not the dll

### encryption handling
- dll uses chrome's `ielevator` com interface to decrypt app-bound master key
- dll sends master key back to injector as hex string via named pipe
- injector uses windows cng apis (`bcryptdecrypt`) for aes-gcm decryption of v20 values
- no go crypto libraries used - all decryption via native windows apis
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
go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o gobound.dll
```

## usage

1. build the dll: `cd dll/main && go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o gobound.dll`
2. host it at an https endpoint (default pulls latest dll from releases page)
3. update the download url in `cmd/main.go` to your https url
4. build the injector: `go build -o gobound.exe cmd/main.go`
5. run `gobound.exe` while chrome is running

## output

`chrome_data.json` contains:
- master key (base64 and hex)
- cookies (profile, host, name, value)
- passwords (profile, url, username, password)
- cards (profile, name on card, expiration, number)

## architecture

### dll (minimal - ~250 lines)
- only responsible for decrypting the master key via chrome's com interface
- init com → decrypt key → send to pipe → exit
- no database handling, no file operations, no sqlite

### injector (full featured - ~950 lines)
- handle scanning and in-memory file extraction
- dll injection using manual pe mapping
- in-memory sqlite database parsing (cookies, passwords, cards)
- aes-gcm decryption using windows cng apis (bcrypt)
- output generation

## dependencies

- github.com/carved4/go-wincall - syscalls and win32 api
- zombiezen.com/go/sqlite - sqlite with in-memory deserialization support
