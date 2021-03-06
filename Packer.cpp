#include "Packer.h"


void PE_FILE::set_sizes(size_t size_ids_, size_t size_dos_stub_, size_t size_inh32_, size_t size_ish_, size_t size_sections_,size_t total_PEsize)
{
	this->size_ids = size_ids_;
	this->size_dos_stub = size_dos_stub_;
	this->size_inh32 = size_inh32_;
	this->size_ish = size_ish_ + sizeof(IMAGE_SECTION_HEADER);
	this->size_sections = size_sections_;
	this->potential_total_size = total_PEsize;
}


std::tuple<bool, std::shared_ptr<char>, std::streampos> OpenBinary(std::wstring filename)
{
	auto flag = false;		
	std::fstream::pos_type size{};  // create file size as fstream object
	std::allocator<char> CharAllocator;
	std::shared_ptr<char> FileBin;
	std::ifstream ifile(filename, std::ios::binary | std::ios::in | std::ios::ate);
	if (ifile.is_open())
	{
		// set size to current file pointer location (tellg method of istream)
		size = ifile.tellg(); 
		// Replace to a make_shared if possible later
		FileBin.reset(new char[size], std::default_delete<char[]>()); 
		// Read file Algorithm
		ifile.seekg(0, std::ios::beg);
		ifile.read(FileBin.get(), size);
		ifile.close();
		// If we got this far , function probably worked perfectly
		flag = true;
		DBGPrint(VALID, "Binary of file loaded in memory");
	}
	return make_tuple(flag, FileBin, size); // return tuple of gathered data
}

PE_FILE ParsePE(std::shared_ptr<char>FileBin)
{
	//DBGPrint( ErrorType::INFO,"Begin Parsing file");
	PE_FILE pefile{};
	const WORD PESignature = 0x5A4D;
	// Copy the IMAGE_DOS_HEADER of the binary
	memcpy_s(&pefile.ids, sizeof(IMAGE_DOS_HEADER), FileBin.get(), sizeof(IMAGE_DOS_HEADER));
	if (pefile.ids.e_magic != PESignature) {
		//Not A PE File
		throw(ErrorReport("Not a Portable Executable File", ErrorType::FATAL));
	}
	// Probably a PE File 
	DBGPrint(ErrorType::INFO,"Detected PE Signature Probably PE File" );
	WORD Architechture = DetectArchitechture(FileBin, pefile.ids.e_lfanew);
	unsigned IMAGE_NT_SIZE;
	switch (Architechture) {
		// Detect Architechture
	case IMAGE_FILE_MACHINE_I386: {
		//x86
		DBGPrint(ErrorType::INFO,"IMAGE_FILE_MACHINE_I386 Detected");
		IMAGE_NT_SIZE = sizeof(IMAGE_NT_HEADERS32);
	}break;
	case IMAGE_FILE_MACHINE_AMD64: {
		//x64
		DBGPrint(ErrorType::INFO, "IMAGE_FILE_MACHINE_AMD64 Detected");
		throw(ErrorReport("IMAGE_FILE_MACHINE_AMD64 Architechture not implemented yet, sorry", ErrorType::FATAL));
	}break;
	case IMAGE_FILE_MACHINE_IA64: {
		DBGPrint( ErrorType::INFO,"IMAGE_FILE_MACHINE_IA64(Itanium) Detected");
		throw(ErrorReport("IMAGE_FILE_MACHINE_IA64(Itanium) Architechture not implemented yet, sorry", ErrorType::FATAL));
	}break;
	default: {
		throw(ErrorReport("IMAGE_FILE_MACHINE_UNKNOWN UNKNOWN", ErrorType::FATAL));
	}break;
	}
	auto PEheaderFileBin = FileBin.get() + pefile.ids.e_lfanew;
	// Copy the IMAGE_NT_HEADERS of the binary
	memcpy_s(&pefile.inh32, IMAGE_NT_SIZE, FileBin.get() + pefile.ids.e_lfanew, IMAGE_NT_SIZE); // address of PE header = e_lfanew
	// Next header pointer offset
	const byte e_lfanew_offset = 0x3c;
	// Next header pointer offset
	// DOS_STUB_PROGRAM offset
	const byte dos_stub_offset = 0x40;
	// DOS_STUB_PROGRAM Size
	size_t stub_size = pefile.ids.e_lfanew - dos_stub_offset; // 0x3c offset of e_lfanew
	//pefile.MS_DOS_STUB.resize(stub_size);
	pefile.MS_DOS_STUB = std::vector<unsigned char>(stub_size, 99);
	// Copy the IMAGE_NT_HEADERS of the binary
	memcpy_s(pefile.MS_DOS_STUB.data(), stub_size, (FileBin.get() + dos_stub_offset ), stub_size);
	// Number of sections
	WORD number_of_sections = pefile.inh32.FileHeader.NumberOfSections;
	if (number_of_sections == 0) {
		// Potential broken or packed file
		throw(ErrorReport("Your file is probably broken or already packed", ErrorType::FATAL));
	}
	// Allocate Space for the section headers in a vector
	pefile.ish.resize(number_of_sections); 
	auto PE_Header = FileBin.get() + pefile.ids.e_lfanew;
	// First Section: PE_header + sizeof FileHeader + sizeof Optional Header
	auto First_Section_Header = PE_Header + 0x18 + pefile.inh32.FileHeader.SizeOfOptionalHeader;
	auto test = PE_Header - sizeof(pefile.ids) - sizeof(IMAGE_NT_HEADERS32) - pefile.MS_DOS_STUB.size();
	// Copy section headers
	//DBGPrint(ErrorType::INFO,"Begin Section headers Copy");
	for (auto i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		memcpy_s(&pefile.ish[i], sizeof(IMAGE_SECTION_HEADER), First_Section_Header + (i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
	}
	//DBGPrint( ErrorType::VALID,"End Section headers Copy");
	// Copy Sections										
	//DBGPrint(ErrorType::INFO,"Begin Section Copy");
		for (auto i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		std::shared_ptr<char> t_char(new char[pefile.ish[i].SizeOfRawData]{}, std::default_delete<char[]>()); // Section
		memcpy_s(t_char.get(), pefile.ish[i].SizeOfRawData, FileBin.get() + pefile.ish[i].PointerToRawData, pefile.ish[i].SizeOfRawData); // copy sections.
		pefile.Sections.push_back(t_char);
	}
	//DBGPrint(ErrorType::VALID,"End Section Copy");
	int sections_size{};
	for (WORD i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		sections_size += pefile.ish[i].SizeOfRawData;
	}
	// Potential total file size (sometimes this calculation is incorrect when the PE file is not well formed)
	size_t total_size = sections_size + pefile.inh32.OptionalHeader.SizeOfHeaders;
	pefile.set_sizes(sizeof(pefile.ids), stub_size, sizeof(pefile.inh32), number_of_sections * sizeof(IMAGE_SECTION_HEADER), sections_size, total_size);
	// Exact Total size must consider space between sections and the file alignment in optional-header
	DBGPrint(ErrorType::VALID,"File parsing Completed");
	return pefile;
}

WORD DetectArchitechture(std::shared_ptr<char>FileBin, LONG HeaderOffset)
{
	const WORD ArchitechtureOffset = 0x2;
	unsigned it = 0;
	// Can easily fuck up needs fix later
	while (*(FileBin.get() + HeaderOffset + ArchitechtureOffset + it) == 0x0)
		++it;
	WORD ArchInformation; 
	memcpy_s(&ArchInformation, sizeof(WORD), FileBin.get() + HeaderOffset + ArchitechtureOffset + it, sizeof(WORD));
	return ArchInformation;
}

DWORD align(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}


void EncryptTextBin(std::tuple<bool, std::shared_ptr<char>, std::streampos>& filebin,int index,char * bin, size_t sz, byte key/*=0xa5*/)
{
	auto DOS_Header = (PIMAGE_DOS_HEADER)std::get<1>(filebin).get();
	auto SH = (PIMAGE_SECTION_HEADER)(std::get<1>(filebin).get() + DOS_Header->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	SH[index].Characteristics = 0xE00000E0;
	XorIncCode(bin, sz, key);
}
void ChangeEP(std::tuple<bool, std::shared_ptr<char>, std::streampos>& bin, ASection& SectionToAdd ) {
	auto PE_Pointer = SectionToAdd.getPE_lfanew();
	// Pointer to the Optional Header inside the Image_NT_Header32 struct
	auto OH = (PIMAGE_OPTIONAL_HEADER)(std::get<1>(bin).get() + PE_Pointer + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	// Pointer to the section headers
	auto SH = (PIMAGE_SECTION_HEADER)(std::get<1>(bin).get() + PE_Pointer + sizeof(IMAGE_NT_HEADERS));
	OH->AddressOfEntryPoint = SH[SectionToAdd.getSectionNumber()].VirtualAddress;
	DBGPrint(VALID, "Successfully changed the entry point to the new section address");
}

void AddSectionHeader(std::tuple<bool, std::shared_ptr<char>, std::streampos>& bin, ASection& SectionToAdd) {
	// add this check later
	DBGPrint(INFO,"Please manually check that there is enough space between the last section header and first section to inject the header in between\n");
    system("pause");
	DWORD PE_Pointer = SectionToAdd.getPE_lfanew();
	// Pointer to the File Header inside the Image_NT_Header32 struct
	auto FH = (PIMAGE_FILE_HEADER)(std::get<1>(bin).get() + PE_Pointer + sizeof(DWORD));
	// Pointer to the Optional Header inside the Image_NT_Header32 struct
	auto OH = (PIMAGE_OPTIONAL_HEADER)(std::get<1>(bin).get() + PE_Pointer + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	// Pointer to the section headers
	auto SH = (PIMAGE_SECTION_HEADER)(std::get<1>(bin).get() + PE_Pointer + sizeof(IMAGE_NT_HEADERS));
	// Preparing the Section header space
	ZeroMemory(&SH[FH->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	// Copying the Section header name
	CopyMemory(&SH[FH->NumberOfSections].Name, SectionToAdd.getSectionName().c_str(), 8);
	// Aligning values with the SectionAlignment(memory) and the FileAlignment and adding it to the section header created
	SH[FH->NumberOfSections].Misc.VirtualSize = align(SectionToAdd.getSectionSize(), OH->SectionAlignment, 0);
	SH[FH->NumberOfSections].VirtualAddress = align(SH[FH->NumberOfSections - 1].Misc.VirtualSize, OH->SectionAlignment, SH[FH->NumberOfSections - 1].VirtualAddress);
	// If the section is not available then SizeOfRawData or PointerToRawData should be 0 or the file will not run obviously
	DWORD AlignedSizeOfRawData = align(SectionToAdd.getSectionSize(), OH->FileAlignment, 0);
	SH[FH->NumberOfSections].SizeOfRawData = AlignedSizeOfRawData;
	SectionToAdd.setAlignedSectionSize(AlignedSizeOfRawData);
	SH[FH->NumberOfSections].PointerToRawData = align(SH[FH->NumberOfSections - 1].SizeOfRawData, OH->FileAlignment, SH[FH->NumberOfSections - 1].PointerToRawData);
	SH[FH->NumberOfSections].Characteristics = SectionToAdd.getCharachteristics();  /*0xE00000E0= IMAGE_SCN_MEM_WRITE  | IMAGE_SCN_CNT_CODE  |
																					 IMAGE_SCN_CNT_UNINITIALIZED_DATA  | IMAGE_SCN_MEM_EXECUTE |
																					 IMAGE_SCN_CNT_INITIALIZED_DATA    | IMAGE_SCN_MEM_READ */
	OH->SizeOfImage = SH[FH->NumberOfSections].VirtualAddress + SH[FH->NumberOfSections].Misc.VirtualSize;
	SectionToAdd.setEP(SH[FH->NumberOfSections ].VirtualAddress);
	SectionToAdd.setSectionNumber(FH->NumberOfSections );
	if (SectionToAdd.getCodeSize() == 0) {
		//SectionToAdd.CodeP = GenerateDefaultCode(SH[FH->NumberOfSections].VirtualAddress, OH->AddressOfEntryPoint + OH->ImageBase, SH[FH->NumberOfSections].SizeOfRawData,);
	}
	// Incrementing the sections number in the File Header
	FH->NumberOfSections += 1;
	DBGPrint(VALID, "Successfully added section header");
}

void AddSectionData(std::tuple<bool, std::shared_ptr<char>, std::streampos>& bin, std::string OutputFileName, ASection& SectionToAdd)
{
	//auto DOS_Header = (PIMAGE_DOS_HEADER)std::get<1>(bin).get(); // get Dos_header if i need it later 
	auto inh32 = (PIMAGE_NT_HEADERS)(std::get<1>(bin).get() + SectionToAdd.getPE_lfanew());
	PIMAGE_SECTION_HEADER FirstSectionHeader = IMAGE_FIRST_SECTION(inh32);
	PIMAGE_SECTION_HEADER LastAddedSection = FirstSectionHeader + (inh32->FileHeader.NumberOfSections - 1);
	size_t BytesToFill =  SectionToAdd.getAlignedSectionSize()- SectionToAdd.getCodeSize();
	std::ofstream os(OutputFileName, std::ios::app | std::ios::out | std::ios::binary);
	if (os.is_open())
	{
		os.write(SectionToAdd.CodeP.get(), SectionToAdd.getCodeSize());
		for (size_t i = 0; i < BytesToFill; ++i)
			os.write("", 1);
		os.close();
		DBGPrint(VALID, "Successfully added the section data");
	}
	else
		throw(ErrorReport("<AddSectionData> Cannot Open file", ErrorType::Error));
}

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

int char2int(char input)
{
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	throw ErrorReport("Invalid key Argument", ErrorType::Error);
}

int FindSection(PE_FILE& pe, const char* sec)
{
	size_t index = 0;
	while (index < pe.inh32.FileHeader.NumberOfSections) {
		if (!strcmp((char*)pe.ish[index].Name, sec))
			return index;
		index++;
	}
	return -1;
}

std::shared_ptr<char> GenerateDefaultCode(DWORD org,DWORD oep,byte key,DWORD SectionRVA,size_t sectionSize)
{
	char DefCode[] = {
		0x50 ,0x56,0x57 ,0x51 ,0x53,0x8D ,0x3D,0x00 ,0x10 ,0x40 ,0x00 ,0x89 ,0xFE ,
		0xB9 ,0x00 ,0xF6 ,0x01 ,0x00 ,0xB3 ,0xA5 ,0xFC ,0xAC ,0x30 ,0xD8 ,0xFE ,0xC3 ,
		0xAA ,0xE2 ,0xF8 ,0x5B ,0x59 ,0x5F ,0x5E ,0x58 ,0xE9 ,0x51 ,0xC7 ,0xFE ,0xFF };
	const size_t PEPreferredBaseAddress = 0x00400000;
	const DWORD jmpOffset = 0x27;
	org += PEPreferredBaseAddress;
	SectionRVA += PEPreferredBaseAddress;
	oep += PEPreferredBaseAddress;
	DWORD dif = oep - org - jmpOffset;
	unsigned char * Pjmp = (unsigned char*) &DefCode[35];
	unsigned char * Pkey = (unsigned char*) &DefCode[19];
	unsigned char * Psize = (unsigned char*) &DefCode[14];
	unsigned char * Psec = (unsigned char *)&DefCode[7];
	CopyMemory(Psec, &SectionRVA, sizeof SectionRVA);
	CopyMemory(Pjmp, &dif, sizeof(dif));
	CopyMemory(Pkey, &key, sizeof(key));
	CopyMemory(Psize, &sectionSize, sizeof(sectionSize));
	std::shared_ptr<char> ret(new char[sizeof DefCode], std::default_delete<char[]>());
	CopyMemory(ret.get(),DefCode,sizeof DefCode);
	DBGPrint(VALID, "Successfully generated binary for injection");
	return ret;
}

void XorIncCode(char* bin, size_t sz, byte key)
{
	size_t i;
	for (i=0;i <sz;++i)
	{
		bin[i] ^=key;
		key++;
	}
}

size_t ASection::getSectionSize() const
{
	return SectionSize;
}

DWORD ASection::getAlignedSectionSize() const
{
	return AlignedSectionSize;
}

void ASection::setAlignedSectionSize(DWORD size)
{
	AlignedSectionSize = size;
}

void ASection::setEP(DWORD newOEP)
{
	NewAddressOEP = newOEP;
}

void ASection::setCodeSize(size_t t)
{
	CodeSize = t;
}

std::string ASection::getSectionName() const
{
	return SectionName;
}

DWORD ASection::getCharachteristics() const
{
	return Charachteristics;
}

LONG ASection::getPE_lfanew() const
{
	return e_lfanew;
}

size_t ASection::getCodeSize() const
{
	return CodeSize;
}

DWORD ASection::getEP() const
{
	return NewAddressOEP;
}

size_t ASection::getSectionNumber() const
{
	return SectionNumber;
}

void ASection::setSectionNumber(size_t num)
{
	SectionNumber = num;
}
