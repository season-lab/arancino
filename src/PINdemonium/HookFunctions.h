#pragma once
#include <map>
#include "pin.H"
#include "ProcessInjectionModule.h"
#include "ProcInfo.h"

class HookFunctions
{
public:
	HookFunctions(void);
	void hookDispatcher(IMG img);

private:
	std::map<string, int> functionsMap;
};

