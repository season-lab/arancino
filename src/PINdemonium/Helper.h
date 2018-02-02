#pragma once
#include "pin.H"
#include <sstream>

namespace W{
		#include "windows.h"
}

class Helper
{
public:
	Helper(void);
	static BOOL existFile (string name);
	static std::vector<std::string> split(const std::string &s, char delim);
	static std::string replaceString(std::string str, const std::string &from, const std::string &to);
	static bool writeBufferToFile(unsigned char *buffer, UINT32 dwBytesToWrite, std::string path);
};

