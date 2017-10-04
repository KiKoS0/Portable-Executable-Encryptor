
#include "Packer.h"
#include <atlconv.h>

enum MainErrorsType{OK,FAILED,UNKNOWN};
//Test Arguments
//Network.exe last.o -s .flm -o output.exe -x .text -e
//test.exe -s .lmg -d -x .rdata -o output.exe
int main(int argc, char* argv[]) {
	USES_CONVERSION;
	int arg = 3;
	std::string HelpString = "Packer Help Guide:\nfile bin [-x SectionToEncrypt] [-e] [-s SectionName][-d]\n	 [/k key] [-o OutputFileName]\n"
		"[file] Portable Executable file name\n"
		"[bin] Binary file to inject in the new section(can be skipped if you don't want	      to use one or to use the default one)\n"
		"  -x [SectionToEncrypt] Finds and encrypts the section data\n"
		"  -e Sets file entry point to the newly added section\n"
		"  -s [SectionName] Force the name of the new section (.kik is the default)\n"
		"  -k [key] Force a new IncXor encryption key (A5 is the default)\n"
		"  -o [OutputFileName] Force an output file name ([file].packed is the default)\n"
		"  -d Force generation of a default code encryptor and use it\n";
	if (argc>=2)
	{
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "/h")) {
			std::cout << HelpString;
			return OK;
		}
	}
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
		if (argv[2][0] == '/' || argv[2][0] == '-') {
			DBGPrint(Error, "No code file");
			arg = 2;
		}
		else {
			DBGPrint(ErrorType::FATAL, "Can't open the code file");
			return FAILED;
		}
	}
	// Default output file name
	std::string FileName = argv[1];
	FileName.append(".packed");
	// Default section name
	std::string SectionName = ".kik";
	// Section to Encrypt
	std::string SectionToEnc;
	// Entry point to the new section
	bool NewSectionIsEP = false;
	// Generate default code
	bool UseDefaultCodeInj = false;
	// Default encryption key
	byte Key = 0xA5;
	// Arguments filter
	while (arg <= argc - 1) {
		std::string command = argv[arg++];
		if (command[0] != '-' && command[0] != '/')
		{
			DBGPrint(FATAL, "Bad parameter use '/' or '-'");
			return FAILED;
		}
		switch (command[1])
		{
		case 'd': {
			UseDefaultCodeInj = 1;
		}break;
		case 'e': {
			NewSectionIsEP = 1;
		}break;
		case 's': {
			if (argc > arg) {
				if (strlen(argv[arg]) <= 8)
					SectionName = argv[arg++];
				else
					DBGPrint(Error, "Section name too long,returned to default: .kik");
			}
			else {
				DBGPrint(FATAL, "No section name");
				return FAILED;
			}
		}break;
		case 'k': {
			if (argc > arg) {
				if (strlen(argv[arg]) == 2) {
					try {
						Key = char2int(argv[arg][0]) * 16 + char2int(argv[arg][1]);
						arg++;
					}
					catch (ErrorReport e) {
						DBGPrint(ErrorType::Error, "Bad Encryption Byte, encryption byte is default : 0xA5");
					}
				}
				else {
					DBGPrint(ErrorType::Error, "Bad Encryption Byte, encryption byte is default : 0xA5");
				}
			}
			else {
				DBGPrint(FATAL, "No key");
				return FAILED;
			}
		}break;
		case 'o': {
			if (argc > arg) {
				FileName = argv[arg++];
			}
			else {
				DBGPrint(FATAL, "No output file name");
				return FAILED;
			}
		}break;
		case 'x': {
			if (argc > arg) {
				if(strlen(argv[arg])<=8)
					SectionToEnc = argv[arg++];
				else {
					DBGPrint(FATAL, "Section to encrypt name is too long");
					return FAILED;
				}
			}
			else {
				DBGPrint(FATAL, "No section to encrypt name");
				return FAILED;
			}
		}break;
		default: {
			DBGPrint(FATAL, "Arguments error");
			std::cout << HelpString;
			return UNKNOWN;
		}break;
		}
	}
	PE_FILE FileMem;
	try
	{
		// Parsing the file is not necessary to get everything to work, you can easily replace its uses with "some" code
		// but i just wanted to add this function for later use and used it btw. 
		FileMem=ParsePE(std::get<1>(bin));
	}
	catch (ErrorReport Er)
	{
		if (Er.getErrorType() == FATAL) {
			Er.Report();
			return FAILED;
		}
	}
	// Injection code size
	size_t CodeSize = std::get<2>(codeBin); 
	// Pointer to the new code in memory
	std::shared_ptr<char> Code(new char[CodeSize],std::default_delete<char[]>());
	// Copy the code to memory
	CopyMemory(Code.get(), std::get<1>(codeBin).get(), CodeSize);
	// Creates the added section characteristics
	ASection section(SectionName, 512, FileMem.ids.e_lfanew, 0xE00000E0, CodeSize, std::get<1>(codeBin));
	AddSectionHeader(bin,section);
	// Encrypt the PE section
	if (!SectionToEnc.empty())
	{
		if (!SectionToEnc.compare(".rsrc") || !SectionToEnc.compare(".rdata") || !SectionToEnc.compare(".idata")) {
			DBGPrint(WARNING, "You are trying to encrypt a sensible OS section this will probably break the file.Continue anyways ? ");
			system("pause");
		};
		if (FindSection(FileMem, ".reloc") >= 0) {
			DBGPrint(WARNING, "Found a relocation section which means that the PE base address is dynamic and encrypting it will corrupt the file.Continue Anyways??");
			system("pause");
		}
		size_t index = FindSection(FileMem, SectionToEnc.c_str());
		if (index < FileMem.inh32.FileHeader.NumberOfSections && index>=0) {
			char* EncSection = std::get<1>(bin).get() + FileMem.ish[index].PointerToRawData;
			EncryptTextBin(bin, index, EncSection, FileMem.ish[index].SizeOfRawData, Key);
			if (UseDefaultCodeInj) {
				section.setCodeSize(39);
				section.CodeP = GenerateDefaultCode(section.getEP(),FileMem.inh32.OptionalHeader.AddressOfEntryPoint,Key,FileMem.ish[index].VirtualAddress,FileMem.ish[index].SizeOfRawData);
			}
		}
		else {
			DBGPrint(FATAL, "Can't find section to encrypt in the file");
			return FAILED;
		}
	}
	else if (UseDefaultCodeInj) {
		DBGPrint(FATAL, "The default code is meant to decrypt an encrypted section at runtime so you can't use it without inputting a section name to encrypt");
		return FAILED;
	}
	// Change the entry point to the added section
	if(NewSectionIsEP)
		ChangeEP(bin, section);
	// Write the new PE file 
	std::ofstream os(FileName, std::ios::ate | std::ios::out | std::ios::binary);
	if (os.is_open()) {
		os.write(std::get<1>(bin).get(), std::get<2>(bin));
		os.close();
		AddSectionData(bin, FileName, section);
	}
	else {
		DBGPrint(FATAL, "<main> Can't open output file for some reason");
		return FAILED;
	}
	DBGPrint(VALID, "Main function ended and program probably succeeded");
	system("pause");
	return OK;
}