#include "ErrorHandling.h"
// Class Methods
std::string ErrorReport::Message() const
{
	return msg;
}

ErrorType ErrorReport::getErrorType() const
{
	return ErrorMsgType;
}

void ErrorReport::Report() const
{
	auto buff =(const char*) msg.c_str();
	DBGPrint(ErrorMsgType, buff);
}

// End Class Methods

void DBGPrint(ErrorType ErrorMsgType, const char* format,...)
{
#ifndef NDEBUG
	switch (ErrorMsgType) {
	case Error:
		std::cout << "[-] ";
		break;
	case INFO:
		std::cout << "[i] ";
		break;
	case VALID:
		std::cout << "[+] ";
		break;
	case FATAL:
		std::cout << "[FATAL] ";
		break;
	default:
		std::cout << "UNKNOWN ERROR== ";
		break;

	}
	va_list args;
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
	std::cout << /*msg*/std::endl;
#endif // _DEBUG

}


