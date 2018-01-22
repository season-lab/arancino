#pragma once
namespace W{
	#include "windows.h"
}
#include <sstream>

typedef void *HANDLE;

class GdbDebugger

{
public:
	static GdbDebugger* getInstance();
	void executeCmd(char* cmd);
	void connectRemote(int port);

private:
	static GdbDebugger* instance;
	W::HANDLE g_hChildStd_IN_Rd;
	W::HANDLE g_hChildStd_IN_Wr;
	W::HANDLE g_hChildStd_OUT_Rd;
	W::HANDLE g_hChildStd_OUT_Wr;
	int remote_port;
	GdbDebugger(void);
	~GdbDebugger(void);
	void CreateChildProcess();
	void ReadFromPipe(void);
	void WriteToPipe(char* cmd);
	void ErrorExit(char* error); 
};

