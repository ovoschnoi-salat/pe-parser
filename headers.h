#ifndef OS_2021_PE_OVOSCHNOI_SALAT_HEADERS_H
#define OS_2021_PE_OVOSCHNOI_SALAT_HEADERS_H

typedef unsigned long long ULONGLONG;
typedef unsigned int DWORD;
typedef unsigned int LONG;
typedef unsigned short WORD;
typedef unsigned char BYTE;

#define IMAGE_DOS_SIGNATURE 0x5A4D // MZ

typedef struct IMAGE_DOS_HEADER { // DOS .EXE header
	WORD e_magic; // Magic number
	WORD e_cblp; // Bytes on last page of file
	WORD e_cp; // Pages in file
	WORD e_crlc; // Relocations
	WORD e_cparhdr; // Size of header in paragraphs
	WORD e_minalloc; // Minimum extra paragraphs needed
	WORD e_maxalloc; // Maximum extra paragraphs needed
	WORD e_ss; // Initial (relative) SS value
	WORD e_sp; // Initial SP value
	WORD e_csum; // Checksum
	WORD e_ip; // Initial IP value
	WORD e_cs; // Initial (relative) CS value
	WORD e_lfarlc; // File address of relocation table
	WORD e_ovno; // Overlay number
	WORD e_res[4]; // Reserved words
	WORD e_oemid; // OEM identifier (for e_oeminfo)
	WORD e_oeminfo; // OEM information; e_oemid specific
	WORD e_res2[10]; // Reserved words
	LONG e_lfanew; //File address of new exe header
} IMAGE_DOS_HEADER;

typedef struct IMAGE_FILE_HEADER {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY;

typedef struct IMAGE_OPTIONAL_HEADER64 {
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	ULONGLONG ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Win32VersionValue;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

// Directory Entries
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0 // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1 // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2 // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3 // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4 // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5 // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6 // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT 7 // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7 // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8 // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS 9 // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10 // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11 // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT 12 // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13 // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14 // COM Runtime descriptor

#define IMAGE_NT_SIGNATURE 0x4550 // PE00

typedef struct IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct IMAGE_SECTION_HEADER {
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER 40

typedef struct IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD Characteristics; // 0 for terminating null import descriptor
		DWORD OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} DUMMYUNIONNAME;
	DWORD TimeDateStamp; // 0 if not bound,
	// -1 if bound, and real date\time stamp in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)
	DWORD ForwarderChain; // -1 if no forwarders
	DWORD Name;
	DWORD FirstThunk; // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct IMAGE_EXPORT_DIRECTORY {
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD Name;
	DWORD Base;
	DWORD NumberOfFunctions;
	DWORD NumberOfNames;
	DWORD AddressOfFunctions; // RVA from base of image
	DWORD AddressOfNames; // RVA from base of image
	DWORD AddressOfNameOrdinals; // RVA from base of image
} IMAGE_EXPORT_DIRECTORY;

#endif //OS_2021_PE_OVOSCHNOI_SALAT_HEADERS_H
