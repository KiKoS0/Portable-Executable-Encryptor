
#include "Packer.h"
#include <atlconv.h>

enum MainErrorsType{OK,WRONGFILETYPE,UNKNOWN};

DWORD align(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}

int main(int argc, char* argv[]) {
	USES_CONVERSION;
	std::cout << sizeof(IMAGE_NT_HEADERS64) << " " << sizeof(IMAGE_NT_HEADERS32) << std::endl;
	std::tuple<bool, std::shared_ptr<char>, std::streampos> bin = OpenBinary(A2T(argv[1]));
	auto hey = std::get<2>(bin);
	std::cout << hey << std::endl;
	PE_FILE FileMem;
	try
	{
		FileMem=ParsePE(std::get<1>(bin));
	}
	catch (ErrorReport Er)
	{
		if (Er.getErrorType() == FATAL) {
			Er.Report();
			return WRONGFILETYPE;
		}
	}
	std::ofstream os("out.exe", std::ios::ate | std::ios::binary | std::ios::out);
	//os.write(std::get<1>(bin).get(), std::get<2>(bin));
	//New
	char* sectionName = ".mysec";
	unsigned sizeOfSection = 400;
	PIMAGE_FILE_HEADER FH = (PIMAGE_FILE_HEADER)(std::get<1>(bin).get() + FileMem.ids.e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER OH = (PIMAGE_OPTIONAL_HEADER)(std::get<1>(bin).get() + FileMem.ids.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(std::get<1>(bin).get() + FileMem.ids.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	ZeroMemory(&SH[FH->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&SH[FH->NumberOfSections].Name, sectionName, 8);
	SH[FH->NumberOfSections].Misc.VirtualSize = align(sizeOfSection, OH->SectionAlignment, 0);
	SH[FH->NumberOfSections].VirtualAddress = align(SH[FH->NumberOfSections - 1].Misc.VirtualSize, OH->SectionAlignment, SH[FH->NumberOfSections - 1].VirtualAddress);
	// If the section is not available SizeOfRawData or PointerToRawData should be 0 or the program will obviously crash
	SH[FH->NumberOfSections].SizeOfRawData = align(sizeOfSection, OH->FileAlignment, 0);
	SH[FH->NumberOfSections].PointerToRawData = align(SH[FH->NumberOfSections - 1].SizeOfRawData, OH->FileAlignment, SH[FH->NumberOfSections - 1].PointerToRawData);
	SH[FH->NumberOfSections].Characteristics = 0xE00000E0;
	OH->SizeOfImage = SH[FH->NumberOfSections].VirtualAddress + SH[FH->NumberOfSections].Misc.VirtualSize;
	FH->NumberOfSections += 1;
	os.write(std::get<1>(bin).get(), std::get<2>(bin));
	os.close();
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)std::get<1>(bin).get();
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(std::get<1>(bin).get() + dos->e_lfanew);
	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
	PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1);
	char str[512] = "KIKOS";
	ZeroMemory(str + 5, sizeof(str) - 5);
	os.open("out.exe", std::ios::app | std::ios::out);
	os.write(str, sizeof(str));
	//End New
	os.close();
	return OK;
}