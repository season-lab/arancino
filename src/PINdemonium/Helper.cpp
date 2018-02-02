#include "Helper.h"

#define MD5LEN  16


Helper::Helper(void)
{
}

/*
Helper function to check file existence
*/
BOOL Helper::existFile (std::string name) {
	if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
}

/*
Split a string into an array based on a delimiter character
*/
std::vector<std::string> Helper::split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    std::stringstream ss(s);
    std::string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}


std::string Helper::replaceString(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}


bool Helper::writeBufferToFile(unsigned char *buffer,UINT32 dwBytesToWrite,string path){

    W::DWORD dwBytesWritten = 0;

	W::HANDLE hFile = W::CreateFile(path.c_str(),           // name of the write
									GENERIC_WRITE,          // open for writing
									0,                      // do not share
									NULL,                   // default security
									CREATE_NEW,             // create new file only
									FILE_ATTRIBUTE_NORMAL,  // normal file
									NULL);                  // no attr. template
	
	// ? : trick to avoid warning from differences between W::BOOL and C++ bool
	return W::WriteFile(hFile,           // open file handle
						buffer,			 // start of data to write
						dwBytesToWrite,  // number of bytes to write
						&dwBytesWritten, // number of bytes that were written
						NULL)            // no overlapped structure
						? true : false; 
}


