#pragma once

#include <stdio.h>
#include "WriteInterval.h"
#include "ProcInfo.h"
#include <ctime>
//#include <direct.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <fstream>
#include "json.h"
namespace W {
	#include "windows.h"
}

//if it is uncommented the result will be saved on file otherwise they'll be printed to stdout
//#define LOG_WRITE_TO_FILE 1 /* DCD */

class Config
{
public:
	static Config* getInstance();
	FILE* Config::getLogFile();
	FILE* Config::getTestFile();
	//getter
	string getBasePath();
	string getCurrentDumpPath();
	string getFixedDumpPath();
	string getCurrentReconstructedImportsPath();
	string getUnfixableDumpPath();
	string getYaraResultPath();
	string getReportPath();
	string getScyllaDumperPath();
	string getScyllaWrapperPath();
	string getScyllaPluginsPath();
	UINT32 getDumpNumber();
	string getFilteredWrites();
	
	
	//utils
	void incrementDumpNumber();
	void Config::closeLogFile();
	//void Config::writeOnTimeLog(string s);
	void setWorking (int dumpAndFixIATstatus);
	void setNewWorkingDirectory(bool isInjection);
	string getWorkingDir();
	string getHeapDir();
	//string getInjectionDir();
	string getYaraExePath();
	string getYaraRulesPath();

	//--------------------------Command line Tuning Flags----------------------------
	static const bool  ATTACH_DEBUGGER;
	static const UINT32 MAX_JUMP_INTER_WRITE_SET_ANALYSIS;
	
	//Tunable from command line
	bool INTER_WRITESET_ANALYSIS_ENABLE; //Trigger the analysis inside a WriteSet in which WxorX is already broken if a Long JMP is encontered (MPress packer)
	UINT32 WRITEINTERVAL_MAX_NUMBER_JMP;
	UINT32 SKIP_DUMP;

	// modes of operation
	bool UNPACKING_MODE;
    bool DBI_SHIELD_MODE;
	
	// PinShield-specific flags
	bool DBI_SHIELD_INS_PATCHING;
	bool DBI_SHIELD_SREAD;
	bool DBI_SHIELD_SWRITE;

	// PINDemonium-specific flags
	bool UNPACKING_ADVANCED_IAT_FIX; // TODO unused?
	bool UNPACKING_POLYMORPHIC_CODE_PATCH;
	bool UNPACKING_NULLIFY_UNKNOWN_IAT_ENTRY; // TODO unused?
	string UNPACKING_SCYLLA_PLUGINS_PATH; // full path
	bool UNPACKING_CALL_PLUGIN_FLAG;

	//Timing attack configurations
	static const UINT32 TIMEOUT_TIMER_SECONDS;
	static const UINT32 TICK_DIVISOR; //this is used in order to lowe the ticks returnedd from GetTickCount and timeGetTime 
	static const UINT32 CC_DIVISOR; // this is used in order to lower the microseconds returned from the QueryPerformanceCounter 
	static const UINT32 KSYSTEM_TIME_DIVISOR; // this is used to lower the LONG lowpart returned from the timeGetTime in the struct _KSYSTEM_TIME inside kuser_shared_data
	static const UINT32 RDTSC_DIVISOR;
	static const UINT32 INTERRUPT_TIME_DIVISOR;
	static const UINT32 SYSTEM_TIME_DIVISOR;

		
private:
	Config::Config();
	static Config* instance;
	FILE *log_file;
	FILE *test_file;

	// initialized via preprocessor directive PIN_FOLDER
	string pin_dir;

	// starts from 0
	UINT32 dump_number;

	// parsed from JSON config file
	string results_path;
	string log_filename;
	string test_filename;
	string report_filename;
	string filtered_writes;		// Which write instructions are filtered (possible values: 'stack teb')
	string scylla_dumper_path;
	string scylla_plugins_path;
	string scylla_wrapper_path;
	string yara_exe_path;
	string yara_rules_path;

	/* computed from other variables */
	string base_path;				// results_path + getCurDateAndTime()
	string working_dir;				// base_path + {"injection_", "dump_"} + dump_number
	string fixed_dump_path;			// working_dir + getProcName() + "_" + dump_number + ".exe"
	string unfixable_dump_path;		// working_dir + "NW_" + getProcName() + "_" + dump_number + ".exe" 
	string heap_dir;				// base_path + "\\HEAP"
	
	//UINT32 timeout;				// DCD disabled by the authors
	//int working;					// DCD commented out as was initialized to -1 and then update by setWorking() but never read
	//string not_working_directory; // DCD became unused after refactoring or was unused before?
	//string cur_list_path;			// Path of the list of the detected function // DCD unused
	//int numberOfBadImports;		// DCD unused

	// helper methods
	string getCurDateAndTime();
	void loadJson(string path);
};

