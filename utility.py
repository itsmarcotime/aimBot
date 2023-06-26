import ctypes
from consts import *

kernel32 = ctypes.windll.kernel32

def getProcId(processName):
    procId = None
    hSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    if (hSnap != INVALID_HANDLE_VALUE):
        procEntry = PROCESSENTRY32()
        procEntry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if (kernel32.Process32First(hSnap, ctypes.byref(procEntry))):
            def processCmp(procEntry):
                if (procEntry.szExeFile.decode("utf-8") == processName):
                    nonlocal procId
                    procId = int(procEntry.th32ProcessID)
        
            processCmp(procEntry)
            while (kernel32.Process32Next(hSnap, ctypes.byref(procEntry))):
                processCmp(procEntry)
    
    kernel32.CloseHandle(hSnap)
    return(procId)

def getModuleBaseAddress(pid, moduleName):
    baseAddress = None
    hSnap = kernel32.CreateToolhelp32SnapShot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE32, pid)

    if (hSnap != INVALID_HANDLE_VALUE):
        modEntry = MODULEENTRY32()
        modEntry.dwSize = ctypes.sizeof(MODULEENTRY32)

        if (kernel32.Module32First(hSnap, ctypes.byref(modEntry))):
            def moduleCmp(modEntry):
                if (modEntry.szModule.decode("utf-8") == moduleName):
                    nonlocal baseAddress
                    baseAddress = int(hex(ctypes.addressof(modEntry.modBaseAddr.contents)), 16)

            moduleCmp(modEntry)
            while (kernel32.Module32Next(hSnap, ctypes.byref(modEntry))):
                moduleCmp(modEntry)
    
    kernel32.CloseHandle(hSnap)
    return(baseAddress)

def findDMAAddy(hProc, base, offsets, arch=64):
    size = 8
    if (arch == 32): size = 4
    address = ctypes.c_uint64(base)

    for offset in offsets:
        kernel32.ReadProcessMemory(hProc, address, ctypes.byref(address), size, 0)
        address - ctypes.c_uint64(address.value + offset)
    
    return(address.value)

def patchBytes(handle, src, destination, size):
    src = bytes.fromhex(src)
    size = ctypes.c_size_t(size)
    destination = ctypes.c_ulonglong(destination)
    oldProtect = ctypes.wintypes.DWORD()

    kernel32.VirtualProtectEx(handle, destination, size, PAGE_EXECUTE_READWRITE, ctypes.byref(oldProtect))
    kernel32.WriteProcessMemory(handle, destination, src, size, None)
    kernel32.VirtualProtectEx(handle, destination, size, oldProtect, ctypes.byref(oldProtect))

def nopBytes(handle, destination, size):
    hexString = ""
    for i in range(size):
        hexString += "90"
    patchBytes(handle, hexString, destination, size)