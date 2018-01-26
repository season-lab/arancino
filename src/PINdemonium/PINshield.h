#pragma once
#include "Pin.h"
#include "Debug.h"
//#include "Log.h"
#include "FilterHandler.h"
#include "PatternMatchModule.h"
#include "FakeReadHandler.h"
#include "FakeWriteHandler.h"

namespace W {
	#include "windows.h"
}

class PINshield
{
public:
	PINshield(void);
	~PINshield(void);
	void avoidEvasion(INS ins);

private:
	PatternMatchModule evasionPatcher;
	FakeReadHandler fakeMemH;
	FakeWriteHandler fakeWriteH;
	BOOL firstRead;
	//void ScanForMappedFiles();	
};

