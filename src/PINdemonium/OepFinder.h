#pragma once

#include "pin.H"
#include "WxorXHandler.h"
#include "Debug.h"
#include "Heuristics.h"
#include "FilterHandler.h"
#include "ProcInfo.h"
#include "Config.h"
#include "Report.h"
#include "md5.h"
#include "Helper.h"
namespace W {
	#include "windows.h"
}
#include "GdbDebugger.h"
#include "ScyllaWrapperInterface.h"
#include "TimeTracker.h"
#include "HeapModule.h"

//return value for isCurrentInOEP function
#define OEPFINDER_SKIPPED_DUMP -4;
#define OEPFINDER_INS_FILTERED -3;
#define OEPFINDER_HEURISTIC_FAIL -2;
#define OEPFINDER_NOT_WXORX_INST -1;
#define OEPFINDER_FOUND_OEP 0;

class OepFinder
{

public:
	OepFinder(void);
	~OepFinder(void);
	UINT32 isCurrentInOEP(INS ins);

private:
	//check if the current instruction is a pushad or a popad
	//if so then set the proper flags in ProcInfo
	void handlePopadAndPushad(INS ins);
	VOID skipCurrentDump(WriteInterval* item, ADDRINT currJMPLength, Config* config);
	BOOL analysis(WriteInterval* item, INS ins, ADDRINT prev_ip, ADDRINT curEip , int dumpAndFixResult);
	void intraWriteSetJMPAnalysis(ADDRINT curEip, ADDRINT prev_ip, INS ins, WriteInterval *item);
	WxorXHandler *wxorxHandler;
	Report *report;
	UINT32 dumpAndFixIAT(ADDRINT curEip, W::DWORD pid, Config* config);
	VOID dumpAndCollectHeap(WriteInterval* item, ADDRINT curEip, int dumpAndFixResult);
};

