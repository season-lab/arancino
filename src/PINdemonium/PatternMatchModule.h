#pragma once

#include "pin.h"
#include <map>
#include <string>
#include "Config.h"

namespace W{
	#include "windows.h"
}

class PatternMatchModule
{
public:
	PatternMatchModule();
	bool patchDispatcher(INS ins,  ADDRINT curEip);

private:
	std::map<string, AFUNPTR> patchesMap;
	AFUNPTR curPatchPointer;
};

