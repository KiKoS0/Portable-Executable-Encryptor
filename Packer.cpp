#include "Packer.h"


void PE_FILE::set_sizes(size_t size_ids_, size_t size_dos_stub_, size_t size_inh32_, size_t size_ish_, size_t size_sections_)
{
	this->size_ids = size_ids_;
	this->size_dos_stub = size_dos_stub_;
	this->size_inh32 = size_inh32_;
	this->size_ish = size_ish_ + sizeof(IMAGE_SECTION_HEADER);
	this->size_sections = size_sections_;
}


std::tuple<bool, std::shared_ptr<char>, std::streampos> OpenBinary(std::wstring filename)
{
	auto flag = false;	// assume failure
	std::fstream::pos_type size{};  // create file size as fstream object
	std::allocator<char> CharAllocator;
	std::shared_ptr<char> FileBin;
	std::ifstream ifile(filename, std::ios::binary | std::ios::in | std::ios::ate);
	if (ifile.is_open())
	{
		size = ifile.tellg();  // set size to current file pointer location (tellg method of istream)
		FileBin.reset(new char[size], std::default_delete<char[]>());
		//Standard get file size algorithm
		ifile.seekg(0, std::ios::beg);
		ifile.read(FileBin.get(), size);
		ifile.close();
		// If we got this far , function probably worked perfectly
		flag = true;
	}
	return make_tuple(flag, FileBin, size); // return tuple of gathered data
}

PE_FILE ParsePE(std::shared_ptr<char>FileBin)
{
	PE_FILE pefile{};
	const WORD PESignature = 0x5A4D;
	// Copy the IMAGE_DOS_HEADER of the binary
	memcpy_s(&pefile.ids, sizeof(IMAGE_DOS_HEADER), FileBin.get(), sizeof(IMAGE_DOS_HEADER));
	if (pefile.ids.e_magic != PESignature) {
		//Not A PE File
		throw(ErrorReport("Not a Portable Executable File", ErrorType::FATAL));
	}
	// Probably a PE File 
	DBGPrint("Detected PE Signature Probably PE File", ErrorType::INFO);
	WORD Architechture = DetectArchitechture(FileBin, pefile.ids.e_lfanew);
	unsigned IMAGE_NT_SIZE;
	switch (Architechture) {
		// Detect Architechture
	case IMAGE_FILE_MACHINE_I386: {
		//x86
		DBGPrint("IMAGE_FILE_MACHINE_I386 Detected", ErrorType::INFO);
		IMAGE_NT_SIZE = sizeof(IMAGE_NT_HEADERS32);
	}break;
	case IMAGE_FILE_MACHINE_AMD64: {
		//x64
		DBGPrint("IMAGE_FILE_MACHINE_AMD64 Detected", ErrorType::INFO);
		throw(ErrorReport("IMAGE_FILE_MACHINE_AMD64 Architechture not implemented yet, sorry", ErrorType::FATAL));
	}break;
	case IMAGE_FILE_MACHINE_IA64: {
		DBGPrint("IMAGE_FILE_MACHINE_IA64(Itanium) Detected", ErrorType::INFO);
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
	pefile.ish.resize(number_of_sections); 

	auto PE_Header = FileBin.get() + pefile.ids.e_lfanew;
	// First Section: PE_header + sizeof FileHeader + sizeof Optional Header
	auto First_Section_Header = PE_Header + 0x18 + pefile.inh32.FileHeader.SizeOfOptionalHeader;
	auto test = PE_Header - sizeof(pefile.ids) - sizeof(IMAGE_NT_HEADERS32) - pefile.MS_DOS_STUB.size();
	// Copy section headers																							
	for (auto i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		memcpy_s(&pefile.ish[i], sizeof(IMAGE_SECTION_HEADER), First_Section_Header + (i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
	}
	// Copy Sections																						
		for (auto i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		std::shared_ptr<char> t_char(new char[pefile.ish[i].SizeOfRawData]{}, std::default_delete<char[]>()); // Section
		memcpy_s(t_char.get(), pefile.ish[i].SizeOfRawData, FileBin.get() + pefile.ish[i].PointerToRawData, pefile.ish[i].SizeOfRawData); // copy sections.
		pefile.Sections.push_back(t_char);
	}
	int sections_size{};
	for (WORD i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		sections_size += pefile.ish[i].SizeOfRawData;
	}
	int tehahast = sections_size + pefile.inh32.OptionalHeader.SizeOfHeaders;
	pefile.set_sizes(sizeof(pefile.ids), stub_size, sizeof(pefile.inh32), number_of_sections * sizeof(IMAGE_SECTION_HEADER), sections_size);
	// Total size must consider space between sections which is huge sometimes and the file alignment in optional-header
	return pefile;
}

WORD DetectArchitechture(std::shared_ptr<char>FileBin, LONG HeaderOffset)
{
	const WORD ArchitechtureOffset = 0x2;
	unsigned it = 0;
	while (*(FileBin.get() + HeaderOffset + ArchitechtureOffset + it) == 0x0)
		++it;
	WORD ArchInformation; 
	memcpy_s(&ArchInformation, sizeof(WORD), FileBin.get() + HeaderOffset + ArchitechtureOffset + it, sizeof(WORD));
	return ArchInformation;
	return 0;
}

