#pragma once

#include "pin.H"
#include "Config.h"
#include "Debug.h"
#include "TimeTracker.h"
#include <time.h>
#include <set>
//#include <unordered_set>
#include "Helper.h"
#include <map>
#include "md5.h"


namespace W{
	#include "windows.h"
	#include <tlhelp32.h>
	#include "Winternl.h"
	#include "winnt.h"
	#include  "Intsafe.h"
}

#define MAX_STACK_SIZE 0x100000    //Used to define the memory range of the stack
#define TEB_SIZE 0xfe0 	
#define KUSER_SHARED_DATA_ADDRESS 0x7ffe0000
#define KUSER_SHARED_DATA_SIZE 0x3e0 


typedef struct PEB {
	W::BYTE padding1[2];
	W::BYTE BeingDebugged ;
	W::BYTE padding2[53];
	W::PVOID ApiSetMap;
	W::BYTE padding3[16];
	W::PVOID ReadOnlySharedMemoryBase;
	W::BYTE padding4[8];
	W::PVOID AnsiCodePageData;
	W::BYTE padding5[52];
	W::PVOID ProcessHeaps;
	W::PVOID GdiSharedHandleTable;
	W::BYTE padding6[336];
	W::PVOID pShimData;
	W::BYTE padding7[12];
	W::PVOID ActivationContextData;
	W::BYTE padding8[4];
	W::PVOID SystemDefaultActivationContextData;
	W::BYTE padding9[52];
	W::PVOID pContextData;
	W::BYTE padding10[4];

}PEB;

struct MemoryRange{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
};

//This struct will track the library loaded
//at program startup
struct LibraryItem{
	ADDRINT StartAddress;
	ADDRINT EndAddress;
	string name;
};

//memorize the PE section information
struct Section {
	ADDRINT begin;
	ADDRINT end;
	string name;

	Section(ADDRINT begin, ADDRINT end, string name) {
		this->begin = begin;
		this->end = end;
		this->name = name;
	}

	Section(SEC &sec) {
		this->begin = SEC_Address(sec);
		this->end = this->begin + SEC_Size(sec);
		this->name = SEC_Name(sec);
	}
};

struct HeapZone {
	ADDRINT begin;
	ADDRINT end;
	UINT32 size;
	UINT32 version;
};

class ProcInfo
{
public:
	//singleton instance
	static ProcInfo* getInstance();
	//distruptor
	~ProcInfo(void);
	/* getter */
	ADDRINT getFirstINSaddress();
	ADDRINT getPrevIp();
	std::vector<Section> getSections();
	std::vector<Section> getProtectedSections();
	float getInitialEntropy();
	BOOL getPushadFlag();
	BOOL getPopadFlag();
	string getProcName();
	clock_t getStartTimer();
	std::set<ADDRINT> getJmpBlacklist(); /* DCD: unordered_set */
	//ADDRINT getPINVMStart();
	//ADDRINT getPINVMEnd();
	std::map<string ,HeapZone> getHeapMap();
	std::map<string,string> getDumpedHZ();

	/* setter */
	void addProcAddresses();
	void setFirstINSaddress(ADDRINT address);
	void setPrevIp(ADDRINT ip);
	void setInitialEntropy(float Entropy);
	void setPushadFlag(BOOL flag);
	void setPopadFlag(BOOL flag);
	void setProcName(string name);
	void setStartTimer(clock_t t);
	void setMainIMGAddress(ADDRINT startAddress, ADDRINT endAddr);	
	/* debug */
	//void PrintStartContext();
	//void PrintCurrContext();
	void PrintSections();
	void printHeapList();
	/* helper */
	void insertSection(Section section);
	string getSectionNameByIp(ADDRINT addr);
	void insertHeapZone(std::string hz_md5, HeapZone heap_zone);
	void insertDumpedHeapZone(std::string hz_data_md5, std::string hz_bin_path);
	void deleteHeapZone(std::string md5_to_remove);
	bool searchHeapMap(ADDRINT ip);
	//HeapZone *getHeapZoneByIndex(UINT32 index);
	float GetEntropy();
	//std::vector<HeapZone> getWhitelistHeap();
	void insertInJmpBlacklist(ADDRINT ip);
	BOOL isInsideJmpBlacklist(ADDRINT ip);
	BOOL isInsideMainIMG(ADDRINT address);
	
	//Protected secions (functions for FakeMemoryHandler)
	VOID addProtectedSection(ADDRINT startAddr, ADDRINT endAddr, const char* secName, const char* libName);
	BOOL isInsideProtectedSection(ADDRINT address);

	//Whitelisted memory (functions for FakeMemoryReader)
	//PEB
	BOOL isPebAddress(ADDRINT addr);
	//TEB
	BOOL isTebAddress(ADDRINT addr);
	VOID addThreadTebAddress();
	//Stack
	BOOL isStackAddress(ADDRINT addr);
	VOID addThreadStackAddress(ADDRINT addr);
	//Library
	BOOL isLibraryInstruction(ADDRINT address);
	BOOL isKnownLibraryInstruction(ADDRINT address);
	VOID addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr);
	BOOL isLibItemDuplicate(ADDRINT address , std::vector<LibraryItem> Libraries);

	BOOL getMemoryRange(ADDRINT address, MemoryRange& range);	
	BOOL addProcessHeapsAndCheckAddress(ADDRINT address);

	//Memory Mapped Files
	BOOL isMappedFileAddress(ADDRINT addr);
	VOID addMappedFilesAddress(ADDRINT startAddr);
	VOID setCurrentMappedFiles();
	VOID printMappedFileAddress();
	//Generic Address
	BOOL isGenericMemoryAddress(ADDRINT address);
	void PrintWhiteListedAddr();

	//Process Fingerprint
	BOOL isInterestingProcess(unsigned int pid);


private:
	typedef std::vector<MemoryRange> MemoryRangeVector;
	static ProcInfo* instance;
	ProcInfo::ProcInfo();
	ADDRINT first_instruction;
	ADDRINT prev_ip;
	std::set<string> interresting_processes_name; /* DCD: was: unordered_set - TODO unused! */
	std::set<unsigned int> interresting_processes_pid; /* DCD: unordered_set - TODO almost unused! */
	MemoryRangeVector stacks;				   //Set of Stack one for each thread
	MemoryRange mainImg;
	MemoryRangeVector tebs;                     //Teb Base Address
	MemoryRangeVector genericMemoryRanges;
	MemoryRangeVector mappedFiles;
	PEB *peb;
	std::vector<Section> Sections;
	std::map<std::string, HeapZone> HeapMap;
	std::vector<HeapZone> WhitelistHeap;
	std::map<std::string, std::string> HeapMapDumped; // TODO use md5string here?
	std::set<ADDRINT> addr_jmp_blacklist; /* DCD: unordered_set */
	std::vector<LibraryItem> knownLibraries;		   //vector of know library loaded
	std::vector<LibraryItem> unknownLibraries;		   //vector of unknow library loaded	
	std::vector<Section> protected_section;			   //vector of protected section ( for example the .text of ntdll is protected ( write on these memory range are redirected to other heap's zone ) )
	float InitialEntropy;
	//track if we found a pushad followed by a popad
	//this is a common technique to restore the initial register status after the unpacking routine
	BOOL pushad_flag;
	BOOL popad_flag;
	string full_proc_name;
	string proc_name;
	clock_t start_timer; 
	//Enumerate Whitelisted Memory Helpers	
	//return the MemoryRange in which the address is mapped
	BOOL isKnownLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr);
	VOID addPebAddress();
	VOID addContextDataAddress();
	VOID addSharedMemoryAddress();
	VOID addAnsiCodePageDataAddress();
	VOID addShimDataAddress();
	VOID addApiSetMapAddress();
	VOID addKUserSharedDataAddress();
	void addMemoryRange(ADDRINT address, MemoryRangeVector &container, const char* logFormat);
	//Library Helpers
	string libToString(LibraryItem lib);
	//long long FindEx(W::HANDLE hProcess, W::LPVOID MemoryStart, W::DWORD MemorySize, W::LPVOID SearchPattern, W::DWORD PatternSize, W::LPBYTE WildCard);
	//void retrieveInterestingPidFromNames();
	



};

