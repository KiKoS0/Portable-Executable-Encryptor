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
	DBGPrint(msg, ErrorMsgType);
}

// End Class Methods

void DBGPrint(std::string msg, ErrorType ErrorMsgType)
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
		std::cout << "ERROR NOT DEFINED== ";
		break;

	}
	std::cout << msg << std::endl;
#endif // _DEBUG

}


