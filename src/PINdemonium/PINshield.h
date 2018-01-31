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

class PINshield {
public:
	PINshield() {};
	void addInstrumentation(INS ins);

private:
	PatternMatchModule evasionPatcher;
	FakeReadHandler fakeReadH;
	FakeWriteHandler fakeWriteH;
	bool isFakeReadInitialized = false;
	//void ScanForMappedFiles();	
};

