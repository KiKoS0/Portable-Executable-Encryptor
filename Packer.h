#pragma once
#ifndef PACKER_H
#define PACKER_H

#include <Windows.h>
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



struct PE_FILE
{
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
	void set_sizes(size_t, size_t, size_t, size_t, size_t);
};


std::tuple<bool, std::shared_ptr<char>, std::streampos> OpenBinary(std::wstring filename);

PE_FILE ParsePE(std::shared_ptr<char>FileBin);

WORD DetectArchitechture(std::shared_ptr<char>FileBin, LONG HeaderOffset);



#endif