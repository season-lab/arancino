#pragma once

#include "pin.h"
#include <map>
#include <string>
#include "Config.h"
//#include <regex> /* TODO */

namespace W{
	#include "windows.h"
}

class PatternMatchModule
{
public:
	PatternMatchModule(void);
	~PatternMatchModule(void);
	bool patchDispatcher(INS ins,  ADDRINT curEip);

private:
	std::map<string, AFUNPTR> patchesMap;
	AFUNPTR curPatchPointer;
};

