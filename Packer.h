#pragma once
#ifndef PACKER_H
#define PACKER_H

#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <memory>
#include <fstream>
#include <tuple>
#include <ostream>
#include <iostream>
#include <string>
#include <future>
#include <filesystem>
#include <vector>
#include "ErrorHandling.h"

class Uncopyable {
protected:
	Uncopyable() {};
	~Uncopyable() {};
private:
	Uncopyable(const Uncopyable&);
	Uncopyable& operator=(const Uncopyable&);
};

class ASection : private Uncopyable {
	std::string SectionName;
	// preferred section size will be aligned in functions later and aligned value will be in AlignedSectionSize
	size_t SectionSize;
	// Initially 0 until a function sets its value
	DWORD AlignedSectionSize;
	size_t CodeSize;
	// Pointer to the new Exe header found in the Image_Dos_Header of the PE
	LONG e_lfanew;
	// Could be easily found here you just combine them by addition "https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx"
	DWORD Charachteristics;
	// Initially 0, could be set to RVA of of a new added section by a function if you want to change the PE OEP
	DWORD NewAddressOEP;
	ASection();
public:
	std::shared_ptr<char> CodeP;
	explicit ASection(std::string sName, size_t SSize, LONG NewExeHeaderP, DWORD Chararacter, size_t CodeS, std::shared_ptr<char> CodePointer) :
		SectionName(sName),
		SectionSize(SSize),
		e_lfanew(NewExeHeaderP),
		Charachteristics(Chararacter),
		CodeP(CodePointer),
		CodeSize(CodeS),
		AlignedSectionSize(0),
		NewAddressOEP(0){};

	// Get Methods
	size_t getSectionSize()const;
	DWORD getAlignedSectionSize()const;
	std::string getSectionName()const;
	DWORD getCharachteristics()const;
	LONG getPE_lfanew()const;
	size_t getCodeSize()const;
	DWORD getOEP() const;
	// Set Methods
	void setAlignedSectionSize(DWORD size);
	void setOEP(DWORD);
};

struct PE_FILE
{
	size_t potential_total_size{};
	size_t size_ids{};
	size_t size_dos_stub{};
	size_t size_inh32{};
	size_t size_ish{};
	size_t size_sections{};
	IMAGE_DOS_HEADER ids;
	std::vector<unsigned char> MS_DOS_STUB;
	IMAGE_NT_HEADERS64 inh64;
	IMAGE_NT_HEADERS32 inh32;
	IMAGE_OPTIONAL_HEADER abc;
	std::vector<IMAGE_SECTION_HEADER> ish;
	std::vector<std::shared_ptr<char>> Sections;
	void set_sizes(size_t, size_t, size_t, size_t, size_t, size_t);
};


std::tuple<bool, std::shared_ptr<char>, std::streampos> OpenBinary(std::wstring filename);

PE_FILE ParsePE(std::shared_ptr<char>FileBin);

WORD DetectArchitechture(std::shared_ptr<char>FileBin, LONG HeaderOffset);

// This function will also change the binary file in memory
void AddSectionHeader(std::tuple<bool, std::shared_ptr<char>, std::streampos>& bin, std::string OutputFileName, ASection& SectionToAdd);

void AddSectionData(std::tuple<bool, std::shared_ptr<char>, std::streampos>& bin, std::string OutputFileName, ASection& SectionToAdd);

void XorCode(char* bin,size_t sz, byte key);

DWORD align(DWORD size, DWORD align, DWORD addr);

#endif