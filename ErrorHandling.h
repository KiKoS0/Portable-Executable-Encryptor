#pragma once

#ifndef PACKER_ERROR_H
#define PACKER_ERROR_H
#include <iostream>
#include <string>

enum ErrorType { Error, INFO, VALID, FATAL };
void DBGPrint(std::string msg, ErrorType ErrorMsgType);


class ErrorReport {
	std::string msg;
	ErrorType ErrorMsgType;
public:
	ErrorReport(std::string m, ErrorType e) : msg(m), ErrorMsgType(e) {};
	std::string Message() const ;
	ErrorType getErrorType() const;
	void Report() const;
};





















#endif