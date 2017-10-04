# Portable Executable Encryptor

This is a small program that i created for educational purposes that creates a new section in a portable executable and injects code into it.

## Getting Started

This build currently supports only x86 files.
You could easily create a new section (header and data) with this program, encrypt an existing section data and inject code into a newly created section.
The program also has a default decryption code(Xor and increment) that you could inject to make hide sections data and makes them decrypt at runtime.
Warning: Runtime decryption will only work on PEs that got linked with a static base address as the program doesn't replace the system loader.

### Build

You just need a 2015 update 3  of visual studio or later to build.

## Parameters
```
[file] Portable Executable file name
[bin] Binary file to inject in the new section(can be skipped if you don't want to use one or to use the default one)
	-x [SectionToEncrypt] Finds and encrypts the section data\n"
	-e Sets file entry point to the newly added section\n"
	-s [SectionName] Force the name of the new section (.kik is the default)
	-k [key] Force a new IncXor encryption key (A5 is the default)
	-o [OutputFileName] Force an output file name ([file].packed is the default)
	-d Force generation of a default code encryptor and use it
```
## Examples
This command for example will encrypt the .text section with 0xA5 as a key, generate a decryption code and inject it in the new section and changes the file entry point to the injectedcode.
```
pck FileToPack.exe -x .text -e -s .NSec -k A5 -o OutputFile.exe -d
```
This one will just create a new section, injects your code into it and changes the entry point to the injected code.
```
pck FileToPack.exe CodeToInject.o -s .NSec -e
```
## Contributing

My code is not that great if not horrible so feel free to contribute.


