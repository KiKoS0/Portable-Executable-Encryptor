
#include "Packer.h"
#include <atlconv.h>

enum MainErrorsType{OK,FAILED,UNKNOWN};



int main(int argc, char* argv[]) {
	USES_CONVERSION;
	if (argc < 3) {
		DBGPrint(ErrorType::FATAL, "Insufficient arguments");
		return FAILED;
	}
	std::tuple<bool, std::shared_ptr<char>, std::streampos> bin = OpenBinary(A2T(argv[1]));
	if (!std::get<0>(bin))
	{
		DBGPrint(ErrorType::FATAL, "Can't open the PE file");
		return FAILED;
	}
	std::tuple<bool, std::shared_ptr<char>, std::streampos> codeBin = OpenBinary(A2T(argv[2]));
	if (!std::get<0>(codeBin))
	{
		DBGPrint(ErrorType::FATAL, "Can't open the code file");
		return FAILED;
	}
	PE_FILE FileMem;
	try
	{
		// Parsing the file is not necessary to get everything to work, you can easily replace its uses with some additional code
		// but i just wanted to add this function for later use and used it. 
		FileMem=ParsePE(std::get<1>(bin));
	}
	catch (ErrorReport Er)
	{
		if (Er.getErrorType() == FATAL) {
			Er.Report();
			return FAILED;
		}
	}
	// Code size to add
	size_t CodeSize = std::get<2>(codeBin); 
	// Pointer to the code to add in memory
	std::shared_ptr<char> Code(new char[CodeSize],std::default_delete<char[]>());
	// Copy the code to memory
	CopyMemory(Code.get(), std::get<1>(codeBin).get(), CodeSize);
	// Default output file name
	std::string FileName = "out.exe.packed";
	std::string SectionName = ".kik";
	// Default section name
	ASection section(SectionName, 50, FileMem.ids.e_lfanew, 0xE00000E0, CodeSize, std::get<1>(codeBin));
	AddSectionHeader(bin,section);
	// Pointer to .text section
	auto* PTextSection = std::get<1>(bin).get() + FileMem.ish[0].PointerToRawData;
	EncryptTextBin(bin,section,PTextSection, FileMem.ish[0].SizeOfRawData, 0xA5);
	ChangeEP(bin, section);
	std::ofstream os(FileName, std::ios::ate | std::ios::out | std::ios::binary);
	os.write(std::get<1>(bin).get(), std::get<2>(bin));
	os.close();
	AddSectionData(bin, FileName, section);
	system("pause");
	return OK;
}