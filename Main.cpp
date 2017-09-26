
#include "Packer.h"
#include <atlconv.h>

enum MainErrorsType{OK,FAILED,UNKNOWN};

// Need it for later use.
DWORD OffsetToRVA(DWORD offset, IMAGE_SECTION_HEADER *is_hdr, unsigned scount)
{
	// Find section holding the Offset
	for (unsigned i = 0; i < scount; i++)
		if ((offset >= is_hdr[i].PointerToRawData) && (offset <= is_hdr[i].PointerToRawData + is_hdr[i].SizeOfRawData))
		{
			// Convert Offset to RVA
			return offset + is_hdr[i].VirtualAddress - is_hdr[i].PointerToRawData;
		}
	return 0;
}

int main(int argc, char* argv[]) {
	USES_CONVERSION;
	std::tuple<bool, std::shared_ptr<char>, std::streampos> bin = OpenBinary(A2T(argv[1]));
	std::tuple<bool, std::shared_ptr<char>, std::streampos> binTest = OpenBinary(A2T("code.asm"));
	std::tuple<bool, std::shared_ptr<char>, std::streampos> codeBin = OpenBinary(A2T("test.o"));
	auto* hey = std::get<1>(binTest).get();
	PE_FILE FileMem;
	try
	{
		FileMem=ParsePE(std::get<1>(bin));
	}
	catch (ErrorReport Er)
	{
		if (Er.getErrorType() == FATAL) {
			Er.Report();
			return FAILED;
		}
	}
	unsigned char TestCode[6] = { 0xE9, 0x6B, 0x2F, 0xFF, 0xFF, 0xC3 };
	// Working Test Code 
	/*	[bits 32]
		[org 0x0041F000]
		jmp 0x00411046
		;nasm -f bin code.nasm -o test.o
	 */
	size_t size = std::get<2>(codeBin); 
	std::shared_ptr<char> Code(new char[size],std::default_delete<char[]>());
	CopyMemory(Code.get(), std::get<1>(codeBin).get(), size);
	std::string FileName = "out.exe";
	ASection section(".kik", 50, FileMem.ids.e_lfanew, 0xE00000E0, size, std::get<1>(codeBin));
	AddSectionHeader(bin, FileName, section);
	AddSectionData(bin, FileName, section);
	system("pause");
	return OK;
}