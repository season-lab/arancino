#include "Config.h"
#include "porting.h"

// rely on the preprocessor
#define	STRINGIFY(x)	#x
#define	TOSTRING(x)		STRINGIFY(x)
#define	PIN_FOLDER		TOSTRING(_PIN_FOLDER)

//constanth path and variable for our logging system

//Tuning Flags
const bool Config::ATTACH_DEBUGGER = false;
const UINT32 Config::MAX_JUMP_INTER_WRITE_SET_ANALYSIS = 20;


// Divisor of the timing 
//if we divide high_1_part and high_2_part with two different values the timeGetTime() doesn't work
//it doesn't work because high_1_part and high_2_part are used in order to understand if the value read for the low_part
//is consistent ( high_1_part == high_2_part -> low_part consistent ) 
const UINT32 Config::KSYSTEM_TIME_DIVISOR = 1;
const UINT32 Config::TICK_DIVISOR = 3000;	//this value is based on exait technique (the time returned is equal to the time returned when the program is not instrumented)
const UINT32 Config::CC_DIVISOR = 3500;	//this value is based on exait technique (the time returned is equal to the time returned when the program is not instrumented)

//the rdtsc works like this :
//store the least 32 significant bit of the returned value in EAX and the most 32 significant bit in EDX ( value = EDX:EAX )
const UINT32 Config::RDTSC_DIVISOR = 400;
const UINT32 Config::INTERRUPT_TIME_DIVISOR = 1000;
const UINT32 Config::SYSTEM_TIME_DIVISOR = 100;

// singleton
Config* Config::instance = 0;

//singleton
Config* Config::getInstance()
{
	if (instance == 0){
		// TODO remove this once validated
		cerr << "Path to JSON config file: " << PIN_FOLDER "\\PINdemoniumDependencies\\config.json" << endl;
		instance = new Config(PIN_FOLDER "\\PINdemoniumDependencies\\config.json");
	}
	return instance;
}

//at the first time open the log file
Config::Config(std::string config_path){

	loadJson(config_path);
	//set the initial dump number



	//W::DebugBreak();
	this->dump_number = 0;
	//build the path for this execution
	this->base_path = results_path + this->getCurDateAndTime() + "\\";
	
	

	//printf("BASE PATH: %s\n" , this->base_path.c_str());

	//mk the directory
	OS_MkDir(this->base_path.c_str(), 777);

	this->heap_dir = this->base_path + "\\HEAP";
	OS_MkDir(this->heap_dir.c_str(), 777);

	//printf("HEAP DIR: %s\n" , this->heap_dir.c_str());


	//create the log and report files
	string log_file_path = this->base_path + log_filename;

	//printf("LOG FILE PATH: %s\n" , log_file_path.c_str());

	this->log_file = fopen(log_file_path.c_str(),"w");	

	// TO FIX Test filename loaded directly without config file
	string test_filename = this->base_path + "testEvasion.txt";
	printf("test_filename is %s\n", test_filename);

	this->test_file = fopen(test_filename.c_str(),"w");
	printf("test_file is %08x\n", test_file);

	this->working = -1;
}

/* ----------------------------- GETTER -----------------------------*/

string Config::getReportPath(){
	return  this->base_path + this->report_filename;
}

string Config::getBasePath(){
	return this->base_path;
}

string Config::getHeapDir(){
	return this->heap_dir;
}

int Config::getDumpNumber(){
	return this->dump_number;
}

string Config::getNotWorkingDumpPath(){
	return this->not_working_path + ProcInfo::getInstance()->getProcName() + "_" + to_string(this->dump_number) + ".exe";
}

string Config::getWorkingDumpPath(){	
	//Creating the output filename string of the current dump (ie finalDump_0.exe or finalDump_1.exe)
	std::string proc_name = ProcInfo::getInstance()->getProcName();

	//_mkdir(this->base_path.c_str());

	this->working_path = this->working_dir + "\\" + proc_name + "_" + to_string(this->dump_number) + ".exe" ;
	return this->working_path;
	
	 
}

string Config::getCurrentDumpPath(){

	string fixed_dump = Config::getInstance()->getWorkingDumpPath();          // path to file generated when scylla is able to fix the IAT and reconstruct the PE
	string not_fixed_dump = Config::getInstance()->getNotWorkingDumpPath();   // path to file generated when scylla is NOT able to and reconstruct the PE
	string dump_to_analyse = "";
	
	if(Helper::existFile(fixed_dump)){ // check if a Scylla fixed dump exist
		dump_to_analyse = fixed_dump;  //we return the fixed dump
	}
	else{
		if(Helper::existFile(not_fixed_dump)){ // check if a not fixed dump exist
			dump_to_analyse = not_fixed_dump; // we return the not fixed dump 
		}
		else{
			MYERRORE("Dump file hasn't been created");  //no file created nothig to return
		}
	}
	return dump_to_analyse;

}

string Config::getCurrentReconstructedImportsPath(){
	return this->base_path + "reconstructed_imports.txt";
}


string Config::getYaraResultPath(){	
 	//Creating the output filename string of the current dump (ie finalDump_0.exe or finalDump_1.exe)
 	return  this->base_path + "yaraResults" + "_" + to_string(this->dump_number) + ".txt" ;
 }

string Config::getScyllaDumperPath(){
	return  this->dep_scylla_dumper_path;
}
string Config::getScyllaWrapperPath(){
	return this->dep_scylla_wrapper_path;
}

string Config::getScyllaPluginsPath(){
	return this->plugins_path;
}

string Config::getFilteredWrites(){
	return this->filtered_writes;
}

string Config::getYaraExePath(){
	return this->yara_exe_path;
}

string Config::getYaraRulesPath(){
	return this->yara_rules_path;
}

//return the file pointer
FILE* Config::getTestFile()
{
	MYINFO("test fieeeeeeeeeeeeeeeee %s",this->test_file);
	return this->test_file;	
}


/* ----------------------------- UTILS -----------------------------*/

void Config::loadJson(string config_path){
	Json::Value root;   // will contains the root value after parsing.
    Json::Reader reader;
    std::ifstream config_file(config_path.c_str(), std::ifstream::binary);
    bool parsingSuccessful = reader.parse( config_file, root, false );
	if ( !parsingSuccessful ){
		printf("Error parsing the json config file: %s",reader.getFormattedErrorMessages().c_str());
		//Can't use LOG since the log path hasn't been loaded yet
	}
	
	results_path = root["results_path"].asString();
	dependecies_path =  root["dependecies_path"].asString();
	plugins_path = root["plugins_path"].asString();
	log_filename = root["log_filename"].asString();
	report_filename = root["report_filename"].asString();
	filtered_writes =root["filtered_writes"].asString();
	timeout =root["timeout"].asInt();
	yara_exe_path = root["yara_exe_path"].asString();
	yara_rules_path  = root["yara_rules_path"].asString();

	dep_scylla_wrapper_path = dependecies_path + "Scylla\\ScyllaWrapper.dll";
	//MYINFO("Load Config %s  %s",PIN_DIRECTORY_PATH_OUTPUT.c_str(),PIN_DIRECTORY_PATH_DEP.c_str());
}

//flush the buffer and close the file
void Config::closeLogFile()
{
	fflush(this->log_file);
	fclose(this->log_file);
}

//return the file pointer
FILE* Config::getLogFile()
{
	#ifdef LOG_WRITE_TO_FILE
		return this->log_file;
	#else
		return stdout;
	#endif
}


//return the current date and time as a string
string Config::getCurDateAndTime(){
  time_t rawtime;
  struct tm * timeinfo;
  char buffer[80];
  time (&rawtime);
  timeinfo = localtime(&rawtime);
  strftime(buffer,80,"%Y_%m_%d_%I_%M_%S",timeinfo);
  return string(buffer);
}

//Increment dump number
void Config::incrementDumpNumber(){
	this->dump_number++;
}


void Config::setNewWorkingDirectory(bool isInjection){
	std::string prefix = "";
	if(isInjection){
		prefix = "injection_";
	}
	else{
		prefix = "dump_";
	}
	
	this->working_dir = this->base_path + prefix + to_string(this->getDumpNumber());

	OS_MkDir(this->working_dir.c_str(), 777);

}

string Config::getWorkingDir(){
	return this->working_dir;
}


void Config::setWorking(int working)
{
	this->working = working;

	std::string working_tag =  this->working_dir + "-[working]";
	std::string not_working_tag =  this->working_dir + "-[not working]";
	std::string not_dumped_tag =  this->working_dir + "-[not dumped]";

	if(working == 0){
		rename(this->working_dir.c_str(),working_tag.c_str());
		this->working_dir = working_tag;
	}
	else{
		rename(this->working_dir.c_str(),not_working_tag.c_str());
		this->working_dir = not_working_tag;
	}
}