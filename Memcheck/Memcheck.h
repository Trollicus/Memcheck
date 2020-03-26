#pragma once
#include <iostream>
#include <algorithm>
#include "memscan.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <sstream>
#include <vector>
#include "BeaEngine\BeaEngine.h"
#include "Keystone\keystone.h"
#include "Minhook\MinHook.h"

const uintptr_t crcptr1 = 0x1f3c1cL;
const uintptr_t crcptr2 = 0x2e5c4fL;
const uintptr_t crcptr3 = 0x2e97dcL;
const uintptr_t crcptr4 = 0x2ebe6cL;
const uintptr_t crcptr5 = 0x2f509cL;
const uintptr_t crcptr6 = 0x2e8d3cL;
const uintptr_t crcptr7 = 0x2435eeL;
const uintptr_t crcptr8 = 0x2e1550L;
const uintptr_t crcptr9 = 0x2ff72dL;
const uintptr_t crcptr10 = 0x2ed22cL;
const uintptr_t crcptr11 = 0x2e126dL;
const uintptr_t crcptr12 = 0x2eae7dL;
const uintptr_t crcptr13 = 0x2f7af0L;
const uintptr_t crcptr14 = 0x312707L;
const uintptr_t crcptr15 = 0x2ed45cL;

namespace Exides
{
	DWORD base(DWORD addr)
	{
		return addr + (DWORD)GetModuleHandle(0);
	}
}

namespace memcheck {
	std::vector<int>silentcheckers;

	DWORD output1 = 0;
	DWORD output2 = 0;
	DWORD memcheckLoc = 0;
	DWORD memcheckLoopEnd = 0;
	DWORD memcheckOriginal = 0;
	DWORD vmpBase = 0;
	DWORD vmpClone = 0;
	DWORD vmpEnd = 0;
	DWORD textBase = 0;
	DWORD textClone = 0;
	DWORD textEnd = 0;

	int clone_section(uintptr_t start, size_t* length) {
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery(reinterpret_cast<void*>(start), &mbi, sizeof(MEMORY_BASIC_INFORMATION));

		uintptr_t sectionClone = reinterpret_cast<uintptr_t>(VirtualAlloc(nullptr, mbi.RegionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
		if (!sectionClone)
			return 0;

		std::memcpy(reinterpret_cast<void*>(sectionClone), reinterpret_cast<void*>(start), mbi.RegionSize);

		*length = mbi.RegionSize;
		return sectionClone;
	}

	// first arg = address memcheck is viewing
	__declspec(naked) void spoof_addr() {
		__asm {
			push ebp
			mov ebp, esp
			mov eax, [ebp + 8]
			mov[output1], eax
			cmp eax, textEnd // is current address outside end of .text
			ja sp_vmp // check if in range of .vmp section
			mov eax, fs: [0x30] 	// .text base from PEB //
			mov eax, [eax + 8]
			cmp[ebp + 8], eax // is current address outside start of .text
			jb sp_vmp // check if in range of .vmp section
			// ..in range push .text clone on stack
			push textClone
			// push .text base on stack
			push eax
			mov eax, [ebp + 8] // read scanned address
			sub eax, [esp]   // subtract from .text base
			add eax, [esp + 4] // add offset to clonebase
			add esp, 8
			// return cloned bytes
			//movsx eax,byte ptr [eax]
			mov[output2], eax
			pop ebp
			ret 4
			sp_vmp:
			mov eax, [ebp + 8] // scanned address
				cmp eax, vmpEnd // is current address outside end of .vmp
				ja sp_exit
				cmp eax, vmpBase // is current address outside start of .vmp
				jb sp_exit
				// ..in range copy .vmp base into eax
				mov eax, vmpBase
				// push .vmp clone on stack
				push vmpClone
				// push .vmp base on stack
				push eax
				mov eax, [ebp + 8] // read scanned address
				sub eax, [esp] // subtract from .vmp base
				add eax, [esp + 4] // add offset to clonebase
				add esp, 8
				// return cloned bytes
				//movsx eax,byte ptr [eax]
				mov[output2], eax
				pop ebp
				ret 4
				sp_exit:
			// return original bytes if outside .vmp / .text
			mov eax, [ebp + 8]
				//movsx eax,byte ptr [eax]
				mov[output2], 0
				pop ebp
				ret 4
		}
	}

	__declspec(naked) void memcheck_hook() {

		__asm {
			mov edx, esp
			pop edx
			mov esp, [esp + 0x8]
			//mov [output],esi
			cmp esi, textEnd // is current address outside end of .text
			ja vmp_check
			mov eax, fs: [0x30]	// .text base from PEB
			mov eax, [eax + 0x8]
			cmp esi, eax // is current address outside start of .text
			jb vmp_check

			sub esp, 0x22C // modify stack ptr because we will intervene
			push textClone // push .text clone on stack
			push eax // push .text base on stack
			mov eax, esi // copy addr being checked into esi
			sub eax, [esp] // subtract addr being checked from .text base to get offset
			add esp, 4
			add dword ptr[esp], eax // add offset to our clone to get real bytes
			jmp checker

			vmp_check :
			cmp esi, vmpEnd	// is current address outside end of .vmp
				ja original;
			cmp esi, vmpBase // is current address outside start of .vmp
				jb original;

			sub esp, 0x22C // modify stack ptr because we will intervene
				mov eax, vmpBase
				push vmpClone // push .vmp clone on stack
				push eax // push .vmp base on stack
				mov eax, esi // copy addr being checked into esi
				sub eax, [esp] // subtract addr being checked from .vmp base to get offset
				add esp, 4
				add dword ptr[esp], eax // add offset to our clone to get real bytes

				checker :
			mov ebx, [ebp - 0x18]
				nop
				hash_start :
			//mov eax,[esi]
			mov eax, [esp] // edit
				mov eax, [eax] // edit
				add eax, esi
				imul eax, eax, 0x1594FE2D
				add eax, [ebp - 0x10]
				rol eax, 0x13
				imul eax, eax, 0xCBB4ABF7
				mov[ebp - 0x10], eax
				lea eax, [esi + 0x4]
				//sub eax,[esi+0x4]
				push eax //
				mov eax, [esp + 0x4]
				mov eax, [eax + 0x4]
				sub[esp], eax
				pop eax //
				add esi, 0x8
				add dword ptr[esp], 0x8 // edit
				imul eax, eax, 0x344B5409
				add eax, [ebp - 0x20]
				rol eax, 0x11
				imul eax, eax, 0x1594FE2D
				mov[ebp - 0x20], eax
				//mov eax,[esi]
				mov eax, [esp] // edit
				mov eax, [eax] // edit
				xor eax, esi
				add esi, 0x4
				add dword ptr[esp], 0x4 // edit
				imul eax, eax, 0x1594FE2D
				add eax, [ebp - 0x1C]
				rol eax, 0xD
				imul eax, eax, 0xCBB4ABF7
				mov[ebp - 0x1C], eax
				//mov eax,[esi]
				mov eax, [esp] // edit
				mov eax, [eax] // edit
				sub eax, esi
				add esi, 0x4
				add dword ptr[esp], 0x4 // edit
				imul eax, eax, 0x344B5409
				add eax, ebx
				rol eax, 0xF
				imul ebx, eax, 0x1594FE2D
				cmp esi, edi
				jb hash_start // <--- Goes to HASH START
				// restore stack ptr //
				add esp, 0x230
				jmp dword ptr ds : [memcheckLoopEnd] // instruction right after jb hash_start
				original :
				jmp dword ptr ds : [memcheckOriginal] // +5 from memcheck hook address (after jmp)
		}
	}


	void patch_silentchecker(int addr) {
		DWORD old;
		DWORD rel;
		DWORD size = 0;
		DWORD patch = reinterpret_cast<DWORD>(VirtualAlloc(nullptr, 1024, MEM_COMMIT, 0x40));
		printf("Patch made [%08X] for silent checker %08X\n", patch, addr);

		int at = addr;
		while (!(*(BYTE*)at == 0x89)) {
			*(BYTE*)(patch + size++) = *(BYTE*)(at++);
		}

		int offset = *(BYTE*)(at + 2);
		int reg2 = (*(BYTE*)(at + 1) % 64) / 8;
		at += 3;

		// mov [ebp+0C],ecx
		// we will put spoof address into [ebp+0C]

		if (reg2 != 0) {
			*(BYTE*)(patch + size++) = 0x50; // push eax
			*(BYTE*)(patch + size++) = 0x8B; // mov eax,reg2
			*(BYTE*)(patch + size++) = 0xC0 + reg2;
			*(BYTE*)(patch + size++) = 0x50; // push eax
		}
		else {
			*(BYTE*)(patch + size++) = 0x50; // push eax
		}

		rel = ((int)spoof_addr - (patch + size)) - 5;
		*(BYTE*)(patch + size++) = 0xE8; // call spoof_addr
		*(DWORD*)(patch + size) = rel;
		size += sizeof(DWORD);

		*(BYTE*)(patch + size++) = 0x89; // mov [ebp+offset],eax
		*(BYTE*)(patch + size++) = 0x45;
		*(BYTE*)(patch + size++) = offset;

		if (reg2 != 0) {
			*(BYTE*)(patch + size++) = 0x58; // pop eax (restore value)
		}

		*(BYTE*)(patch + size++) = 0x8B; // mov reg2,[ebp+offset]
		*(BYTE*)(patch + size++) = 0x45 + (reg2 * 8);
		*(BYTE*)(patch + size++) = offset;

		// jmp back after the mov [ebp+...],... instruction
		rel = (at - (patch + size)) - 5;
		*(BYTE*)(patch + size++) = 0xE9;
		*(DWORD*)(patch + size) = rel;
		size += 4;

		// Place hook
		VirtualProtect((void*)addr, 5, 0x40, &old);
		rel = (patch - addr) - 5;
		*(BYTE*)(addr) = 0xE9;
		*(DWORD*)(addr + 1) = rel;
		VirtualProtect((void*)addr, 5, old, &old);
	}

	/*void patch_silentchecker(int addr) {
		int size = 0;
		int at = addr;
		int hash_end = at;

		// Scan for the JNE that causes the hash to
		// jump back to a start address,
		// which is just ahead of the AOB we scan
		while (!(*(BYTE*)(hash_end) == 0x75 && *(BYTE*)(hash_end + 1) > 0x8F && *(BYTE*)(hash_end + 1) < 0xC0)) {
			hash_end++;
		}
		int hash_start = (hash_end + 2 + *(CHAR*)(hash_end + 1));

		DWORD patch = reinterpret_cast<DWORD>(VirtualAlloc(nullptr, 1024, MEM_COMMIT, 0x40));
		printf("Patch made [%08X] for silent checker %08X\n", patch, addr);

		// to avoid detection
		// sub esp, 230 (len: 6)
	   // BYTE reserve_mem1[] = { 0x81,0xEC,0x30,0x02,0x00,0x00 };
	   // memcpy((void*)patch, &reserve_mem1, 6);
	   /// size = 6;

		while (at < hash_end + 2) {
			// if we stumble upon a movsx instruction . . .
			if (*(WORD*)at == 0xBE0F) {
				// some basic x86 disassembly
				BYTE v = *(BYTE*)(at + 2);
				BYTE regoffset;
				BOOL has_regoffset = (v > 0x3F);
				v = v % 64;
				int reg1 = v / 8;
				int reg2 = v % 8;

				if (has_regoffset){
					regoffset = *(BYTE*)(at + 3);
				} else {
					regoffset = 0x00;
				}

				if (reg1 != 0) { // if the first register is NOT EAX
					*(BYTE*)(patch + size++) = 0x50; // push eax
					*(BYTE*)(patch + size++) = 0x8D; // lea eax, [reg2 (+/-) offset]
					*(BYTE*)(patch + size++) = 0x40 + reg2;
					*(BYTE*)(patch + size++) = regoffset;
					*(BYTE*)(patch + size++) = 0x50; // push eax

					DWORD rel = ((int)spoof_addr - (patch + size)) - 5;
					*(BYTE*)(patch + size++) = 0xE8; // call spoof_addr
					*(DWORD*)(patch + size) = rel;
					size += sizeof(DWORD);

					*(BYTE*)(patch + size++) = 0x8B; // mov reg1, eax(return value/spoofed addr)
					*(BYTE*)(patch + size++) = 0xC0 + (reg1 * 8);
					*(BYTE*)(patch + size++) = 0x58; // pop eax
				} else { // if the first register is EAX
					*(BYTE*)(patch + size++) = 0x8D; // lea eax, [reg2 (+/-) offset]
					*(BYTE*)(patch + size++) = 0x40 + reg2;
					*(BYTE*)(patch + size++) = regoffset;
					*(BYTE*)(patch + size++) = 0x50; // push eax

					DWORD rel = ((int)spoof_addr - (patch + size)) - 5;
					*(BYTE*)(patch + size++) = 0xE8; // call spoof_addr
					*(DWORD*)(patch + size) = rel;
					size += sizeof(DWORD);
				}



				// finally, skip the movsx instruction
				// we've rigged it
				if (has_regoffset) {
					at += 4;
				} else {
					at += 3;
				}
			}  else if (at == hash_end) {
				// we want to re-format the "jne" so
				// that it jumps back to where our hash
				// starts in our patched replica.
				int diff = hash_start - addr;
				int rel = (patch + diff) - (patch + size) - 6;
				*(BYTE*)(patch + size++) = 0x0F; // LONG JNE
				*(BYTE*)(patch + size++) = 0x85;
				*(int*)(patch + size) = rel;
				size += sizeof(int);

				// add esp, 230 (len: 6)
			   // BYTE reserve_mem2[] = { 0x81,0xC4,0x30,0x02,0x00,0x00 };
			   // memcpy((void*)(patch + size), &reserve_mem2, 6);
			   // size += 6;

				break;
			} else {
				*(BYTE*)(patch + size++) = *(BYTE*)(at++);
			}
		}

		// Place hook
		DWORD old;
		VirtualProtect((void*)addr, 5, 0x40, &old);
		DWORD rel = ((int)patch - addr) - 5;
		*(BYTE*)(addr) = 0xE9;
		*(DWORD*)(addr + 1) = rel;
		VirtualProtect((void*)addr, 5, old, &old);
	}*/

	void patch_memcheck(int addr) {
		// Place hook
		DWORD old;
		VirtualProtect((void*)addr, 7, 0x40, &old);
		DWORD rel = ((int)memcheck_hook - addr) - 5;
		*(BYTE*)(addr) = 0xE9;
		*(DWORD*)(addr + 1) = rel;
		*(WORD*)(addr + 5) = 0x9090;
		VirtualProtect((void*)addr, 7, old, &old);
		printf("Memcheck core function patched.\n");
	}

	namespace memutil
	{
		static uintptr_t rebase(uintptr_t address)
		{
			return address - 0x400000 + reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
		}
	}

	size_t calculateJumpOffset(uintptr_t addr)
	{
		std::string ignoreList[] = {
			"jnc", "jmp" // jumps to ignore
		};

		// size of buffer
		const size_t szBlock = 0x80;

		// Create a new buffer
		void* pBuffer = malloc(szBlock);

		// Nop the buffer
		memset(pBuffer, 0x90, szBlock);

		// Copy instructions to buffer
		memcpy(pBuffer, (void*)*(int*)&addr, szBlock);

		// Initialize Disasm structure
		DISASM lol;

		memset(&lol, 0, sizeof(lol));
		lol.Options = Tabulation + MasmSyntax;
		lol.Archi = NULL; //IA-32 Architecture//

		// Set Instruction Pointer
		lol.EIP = (int)pBuffer;
		lol.VirtualAddr = addr;

		// Calculate End Address
		UIntPtr EndCodeSection = (int)pBuffer + szBlock;

		// Disassembly error
		int DisAsmErr = false;

		while (!DisAsmErr)
		{
			lol.SecurityBlock = szBlock;

			//size_t len = PDISASM;

			//if (len == OUT_OF_BLOCK) {
			//
			//DisAsmErr = true;
			//}
			//else if (len == UNKNOWN_OPCODE) {
			//	DisAsmErr = true;
			//}
				/* if no error -> filter instructions */

				bool ignoreJump = false;  // ignore jumps in blacklist

				if (lol.Instruction.BranchType) // check if jump instruction //
				{
					for (const auto& _jumps : ignoreList)
					{
						std::string op = &lol.Instruction.Mnemonic[0];

						// remove spaces from mnemonic
						op.erase(remove(op.begin(), op.end(), ' '), op.end());

						if (op == _jumps)
							ignoreJump = true;
					}

					if (!ignoreJump)
					{
						free(pBuffer);
						return ((lol.VirtualAddr) - addr);
					}
				}

				/* next instruction(s) */

				lol.EIP = lol.EIP;

				lol.VirtualAddr = lol.VirtualAddr;

				if (lol.EIP >= EndCodeSection) {
					DisAsmErr = true;
				}
		}

		free(pBuffer);

		return -1;
	}

	void pause() {
		THREADENTRY32 te32;
		te32.dwSize = sizeof(THREADENTRY32);
		HANDLE hThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
		if (Thread32First(hThreads, &te32)) {
			while (Thread32Next(hThreads, &te32)) {
				if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId()) {
					HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, false, te32.th32ThreadID);
					SuspendThread(hThread);
					CloseHandle(hThread);
				}
			}
		}
		CloseHandle(hThreads);
	}

	void resume() {
		THREADENTRY32 te32;
		te32.dwSize = sizeof(THREADENTRY32);
		HANDLE hThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
		if (Thread32First(hThreads, &te32)) {
			while (Thread32Next(hThreads, &te32)) {
				if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId()) {
					HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, false, te32.th32ThreadID);
					ResumeThread(hThread);
					CloseHandle(hThread);
				}
			}
		}
		CloseHandle(hThreads);
	}

	void write_memory(uintptr_t addr, std::string patch) {

		DWORD oldProtect;

		const size_t dwSize = patch.length();

		VirtualProtect((LPVOID)addr, dwSize,
			PAGE_EXECUTE_READWRITE,
			(PDWORD)&oldProtect);

		for (size_t i = 0; i < dwSize; i++)
			((unsigned char*)addr)[i] = ((unsigned char*)&patch)[i];

		VirtualProtect((LPVOID)addr, dwSize,
			oldProtect, (PDWORD)&oldProtect);

	};


	void init() {
		int origText = memutil::rebase(0x401000);
		size_t textLength;
		textClone = clone_section(origText, &textLength) - 0x1000;

		// go to RobloxPlayerBeta.exe in memview,
		// and go here:
		// 2E 76 6D 70 30 00 00 00 D7 23 1B 00 00 E0 FF 01 .vmp0... #...  .
		// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
		// 00 00 00 00 60 00 00 60 2E 76 6D 70 31 00 00 00 ....`..`.vmp1...
		// 50 27 CA 00 00 10 1B 02 00 28 CA 00 00 0C 29 01 P' ......( ...). <-------
		//             ^^^^^^^^^^^
		int origVmp = /*memutil::rebase(0x1A398FE);*/ /*memutil::rebase(0x1FFE000);*/ memutil::rebase(0x2017863	);
		size_t vmpLength;
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery(reinterpret_cast<void*>(origVmp), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		origVmp = (int)mbi.BaseAddress;
		vmpClone = clone_section(origVmp, &vmpLength);

		textEnd = origText + textLength;
		textBase = origText;
		vmpEnd = origVmp + vmpLength;
		vmpBase = origVmp;

		memcheckLoc = memutil::rebase(0x5F62DF);
		//memcheckLoopEnd = memcheckLoc + calculateJumpOffset(memcheckLoc);
		memcheckOriginal = memcheckLoc + 5;

		printf("Scanning for silentcheckers...\n");
		for (int res : memscan::scan("2B??8D??????89????C1")) {
			// Check for a long or short `jae` instruction
			if (*(WORD*)(res - 6) == 0x830F || *(BYTE*)(res - 2) == 0x73) {
				silentcheckers.push_back(res);
			}
		}

		printf("Silent checks: %d.\n", silentcheckers.size());
		printf("text copy: %08X, size: %08X.\n", textClone, textLength);

		//write_memory(memcheckLoc + 5, "\x90\x90");

	}

	void load_bypass() {
		init();
		patch_memcheck(memcheckLoc);
		for (DWORD addr : silentcheckers) {
			patch_silentchecker(addr);
		}
	}
}