#include <stdio.h>
#include <string.h>
#include "headers.h"

int checkMZ(FILE *in) {
	unsigned int dosHeaderSize = sizeof(IMAGE_DOS_HEADER);
	IMAGE_DOS_HEADER header;
	if (fread(&header, dosHeaderSize, 1, in) != 1)
		return -1;
	if (header.e_magic != IMAGE_DOS_SIGNATURE)
		return 1;
	if (fseek(in, header.e_lfanew, SEEK_SET))
		return -1;
	return 0;
}

int checkPe(FILE *in) {
	int peHeaderSize = sizeof(IMAGE_NT_HEADERS64);
	IMAGE_NT_HEADERS64 peHeader;
	int r = checkMZ(in);
	if (r)
		return r;
	if (fread(&peHeader, peHeaderSize, 1, in) != 1)
		return -1;
	if (peHeader.Signature != IMAGE_NT_SIGNATURE)
		return 1;
	return 0;
}

int printStringFromFile(FILE *in) {
	while (1) {
		int buf;
		if ((buf = fgetc(in)) == EOF)
			return -1;
		if (buf == '\0')
			break;
		putchar(buf);
	}
	putchar('\n');
	return 0;
}

int printImportFunctions(FILE *in) {
	int peHeaderSize = sizeof(IMAGE_NT_HEADERS64);
	IMAGE_NT_HEADERS64 peHeader;
	int r = checkMZ(in);
	if (r)
		return r;
	if (fread(&peHeader, peHeaderSize, 1, in) != 1)
		return -1;
	if (peHeader.Signature != IMAGE_NT_SIGNATURE)
		return 1;
	unsigned int importTableRVA = peHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (importTableRVA == 0)
		return 1;
	IMAGE_SECTION_HEADER sectionHeader;
	while (1) {
		if (fread(&sectionHeader, IMAGE_SIZEOF_SECTION_HEADER, 1, in) != 1)
			return -1;
		if (importTableRVA >= sectionHeader.VirtualAddress
				&& importTableRVA < sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize) {
			break;
		}
	}
	int transformRVAToPtr = (int)sectionHeader.PointerToRawData - (int)sectionHeader.VirtualAddress;
	if (fseek(in, importTableRVA + transformRVAToPtr, SEEK_SET))
		return -1;
	fpos_t p;
	IMAGE_IMPORT_DESCRIPTOR importDescriptor;
	while (1) {
		if (fread(&importDescriptor, sizeof(struct IMAGE_IMPORT_DESCRIPTOR), 1, in) != 1)
			return -1;
		if (!importDescriptor.DUMMYUNIONNAME.Characteristics)
			return 0;
		if (fgetpos(in, &p))
			return -1;
		if (fseek(in, importDescriptor.Name + transformRVAToPtr, SEEK_SET))
			return -1;
		if (printStringFromFile(in))
			return -1;
		unsigned long long fAddress;
		fpos_t p2;
		if (fseek(in, importDescriptor.DUMMYUNIONNAME.OriginalFirstThunk + transformRVAToPtr, SEEK_SET))
			return -1;
		while (1) {
			if (fread(&fAddress, 8, 1, in) != 1 || fgetpos(in, &p2))
				return -1;
			if (fAddress == 0)
				break;
			if ((fAddress & 0x8000000000000000) == 0) {
				if (fseek(in, (fAddress & 0x7FFFFFFF) + transformRVAToPtr + 2, SEEK_SET))
					return -1;
				printf("    ");
				if (printStringFromFile(in))
					return -1;
				if (fsetpos(in, &p2))
					return -1;
			}
		}
		if (fsetpos(in, &p))
			return -1;
	}
}

int printExportFunctions(FILE *in) {
	int peHeaderSize = sizeof(IMAGE_NT_HEADERS64);
	IMAGE_NT_HEADERS64 peHeader;
	int r = checkMZ(in);
	if (r)
		return r;
	if (fread(&peHeader, peHeaderSize, 1, in) != 1)
		return -1;
	if (peHeader.Signature != IMAGE_NT_SIGNATURE)
		return 1;
	unsigned int exportTableRVA = peHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportTableRVA == 0)
		return 0;
	IMAGE_SECTION_HEADER sectionHeader;
	while (1) {
		if (fread(&sectionHeader, IMAGE_SIZEOF_SECTION_HEADER, 1, in) != 1)
			return -1;
		if (exportTableRVA >= sectionHeader.VirtualAddress
				&& exportTableRVA < sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize) {
			break;
		}
	}
	int transformRVAToPtr = (int)sectionHeader.PointerToRawData - (int)sectionHeader.VirtualAddress;
	if (fseek(in, exportTableRVA + transformRVAToPtr, SEEK_SET))
		return -1;
	IMAGE_EXPORT_DIRECTORY exportDirectory;
	if (fread(&exportDirectory, sizeof(struct IMAGE_EXPORT_DIRECTORY), 1, in) != 1)
		return -1;
	unsigned int fAddress;
	for (unsigned int i = 0; i < exportDirectory.NumberOfNames; ++i) {
		if (fseek(in, exportDirectory.AddressOfNames + transformRVAToPtr + 4 * i, SEEK_SET) ||
				fread(&fAddress, 4, 1, in) != 1)
			return -1;
		if (fAddress == 0)
			return 0;
		if (fseek(in, fAddress + transformRVAToPtr, SEEK_SET) || printStringFromFile(in))
			return -1;
	}
}

int main(int argc, char **args) {
	if (argc != 3) {
		fprintf(stderr, "Incorrect input arguments\n"
						"This program expect launching with 2 arguments:"
						" pe-parser <operation> <inputPeFileName>\n"
						"Where:\n"
						"   operation - name of operation to proceed\n"
						"		[\'is-pe\', \'import-functions\', \'export-functions\']\n"
						"   inputPeFileName - name of input pe file\n");
		return -1;
	}
	FILE *in = fopen(args[2], "rb");
	if (in == NULL) {
		fprintf(stderr, "Error opening input pe file");
		return -1;
	}
	if (strcmp(args[1], "is-pe") == 0) {
		int r = checkPe(in);
		if (r == 0) {
			printf("PE");
			goto success;
		} else {
			printf("Not PE");
			goto incorrect;
		}
	} else if (strcmp(args[1], "import-functions") == 0) {
		int r = printImportFunctions(in);
		if (r == 0)
			goto success;
		else if (r > 0)
			goto incorrect;
	} else if (strcmp(args[1], "export-functions") == 0) {
		int r = printExportFunctions(in);
		if (r == 0)
			goto success;
		else if (r > 0)
			goto incorrect;
	} else {
		fprintf(stderr, "Incorrect operation argument: \'%s\'", args[1]);
		goto incorrect;
	}
	fprintf(stderr, "Error while parsing file");
	fclose(in);
	return -1;
success:
	fclose(in);
	return 0;
incorrect:
	fclose(in);
	return 1;
}
