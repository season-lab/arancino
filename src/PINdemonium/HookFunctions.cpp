#include "HookFunctions.h"
#include "porting.h"

#define VIRTUALFREE_INDEX 0
#define CREATEPROCESS_INDEX 1

// commented out in the released code
#define VIRTUALALLOC_INDEX 2
#define RTLALLOCATEHEAP_INDEX 3
#define ISDEBUGGERPRESENT_INDEX 4
#define RTLREALLOCATEHEAP_INDEX 5

HookFunctions::HookFunctions(void)
{
	this->functionsMap.insert( std::pair<string,int>("VirtualFree",VIRTUALFREE_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("CreateProcessInternalW",CREATEPROCESS_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("CreateProcessInternalA",CREATEPROCESS_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("CreateProcessInternal",CREATEPROCESS_INDEX) );
	/*
	this->functionsMap.insert( std::pair<string,int>("RtlAllocateHeap",RTLALLOCATEHEAP_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("IsDebuggerPresent",ISDEBUGGERPRESENT_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("RtlReAllocateHeap",RTLREALLOCATEHEAP_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("VirtualQuery",VIRTUALQUERY_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("VirtualProtect",VIRTUALPROTECT_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("VirtualQueryEx",VIRTUALQUERYEX_INDEX) );
	CsrFreeCaptureBufferHook
	*/
}

//----------------------------- HOOKED FUNCTIONS -----------------------------//

// hook the VirtualAlloc() in order to retrieve the memory range allocated and build ours data structures
// NOT USED ANYMORE, WE HOOKED THE NtAllocateVirtualMemory syscall in order to be more generic ( see HookSyscalls.cpp row 126 )
VOID VirtualAllocHook(UINT32 virtual_alloc_size , UINT32 ret_heap_address ){  
	ProcInfo *proc_info = ProcInfo::getInstance();
	HeapZone hz;
	hz.begin = ret_heap_address;
	hz.size = virtual_alloc_size;
	hz.end = ret_heap_address + virtual_alloc_size;  
	hz.version = 0;
	MYINFO("Virtualloc insert in Heap Zone %08x -> %08x",hz.begin,hz.end);
	//saving this heap zone in the map inside ProcInfo

	char *hz_data = (char *)malloc(hz.size);
	PIN_SafeCopy(hz_data , (void const *)hz.begin , hz.size);

	std::string heap_key = to_string((unsigned long long)hz.begin) + to_string((unsigned long long)hz.end); /* DCD: _ULonglong */

	std::string hz_md5 = md5(heap_key);

	proc_info->insertHeapZone(hz_md5,hz); 

	free(hz_data);
}

//hook the  HeapAllocHook() in order to retrieve the memory range allocated and build ours data structures
static HeapZone prev_heap_alloc;
std::string prev_md5;

VOID RtlAllocateHeapHook(W::SIZE_T heap_alloc_size, ADDRINT ret_heap_address){	 
	if (heap_alloc_size == 0 ){
		return;
	}
	ProcInfo *proc_info = ProcInfo::getInstance();

	//need this code because sometimes RTLAllocHeap is invoked twice (because of the IPOINT_AFTER insert)and the second time is the correct one
	if (prev_heap_alloc.begin == ret_heap_address){
		proc_info->deleteHeapZone(prev_md5);
	}
	
	HeapZone hz;
	hz.begin = ret_heap_address;
	hz.size = heap_alloc_size;
	hz.end = ret_heap_address + heap_alloc_size;
	hz.version = 0;
	prev_heap_alloc =hz;
	 
	char *hz_data = (char*)malloc(hz.size);
	PIN_SafeCopy(hz_data, (void const *)hz.begin, hz.size);

	std::string heap_key = to_string(hz.begin) + to_string(hz.end); /* DCD: why they were both casted to _ULonglong ?? */
	std::string hz_md5 = md5(heap_key);

	proc_info->insertHeapZone(hz_md5,hz);
	free(hz_data);
}

// undocumented NTAPI function
// HeapReAlloc maps directly to RtlReAllocateHeap
/*NTSYSAPI PVOID NTAPI RtlReAllocateHeap(
							IN PVOID	HeapHandle,
							IN ULONG	Flags,
							IN PVOID	MemoryPointer,
							IN ULONG	Size);*/
VOID RtlReAllocateHeapHook(ADDRINT heap_address, W::ULONG size){	
	ProcInfo *proc_info = ProcInfo::getInstance();
	HeapZone hz;
	hz.begin = heap_address;
	hz.size = size;
	hz.end = heap_address + size;
	hz.version = 0;

	char *hz_data = (char *)malloc(hz.size);
	PIN_SafeCopy(hz_data , (void const *)hz.begin , hz.size);

	std::string heap_key = to_string(hz.begin) + to_string(hz.end); /* DCD: why they were both casted to _ULonglong ?? */
	std::string hz_md5 = md5(heap_key);

	proc_info->insertHeapZone(hz_md5,hz);
	free(hz_data);
}

VOID VirtualFreeHook(ADDRINT address_to_free){
	MYINFO("Calling VirtualFree of the address %08x\n" , address_to_free);
	ProcInfo *pInfo = ProcInfo::getInstance();
	std::map<string,HeapZone> HeapMap = pInfo->getHeapMap();
	
	std::string md5_to_remove;

	for (std::map<std::string,HeapZone>::iterator it=HeapMap.begin(); it!=HeapMap.end(); ++it){
		if (address_to_free == it->second.begin){
			md5_to_remove = it->first;
			pInfo->deleteHeapZone(it->first); // DCD should not be empty
			return;
		}
	}
}

/*
VOID VirtualQueryHook (W::LPCVOID baseAddress, W::PMEMORY_BASIC_INFORMATION mbi, W::SIZE_T *numBytes) {
	FakeReadHandler* fake_memory_handler = new FakeReadHandler();
	if (!fake_memory_handler->isAddrInWhiteList((ADDRINT)baseAddress) && numBytes && mbi) {
		*numBytes = 0;
		mbi->State = MEM_FREE;
	}
}

VOID VirtualQueryExHook (W::HANDLE hProcess, W::LPCVOID baseAddress, W::PMEMORY_BASIC_INFORMATION mbi, W::SIZE_T *numBytes) {
	if (hProcess == W::GetCurrentProcess())
		VirtualQueryHook(baseAddress, mbi, numBytes);
}
*/
//REMEMBER!!! : PIN wants a function pointer in the AFUNCPTR agument!!!
//avoid the detection of the debugger replacing the function IsDebuggerPresent() with a new one that returns always false
//very basic way to avoid this anti-debugging technique
bool * IsDebuggerPresentHook(){
	return false;
}

VOID CreateProcessHookEntry(W::LPWSTR lpApplicationName){
	MYINFO("Started CreateProcessInternal application name %S", lpApplicationName);
	ProcessInjectionModule::getInstance()->setInsideCreateProcess();
}


//----------------------------- HOOK DISPATCHER -----------------------------//

//scan the image and try to hook all the function specified above
void HookFunctions::hookDispatcher(IMG img){
	// iterate over functions that we want to hook/replace
	for (std::map<string,int>::iterator item = this->functionsMap.begin(); item != this->functionsMap.end(); ++item){
		const char * func_name = item->first.c_str();
		RTN rtn = RTN_FindByName(img, func_name); // get pointer to the function
		
		if (rtn != RTN_Invalid()) {
			int index = item->second;
			ADDRINT va_address = RTN_Address(rtn);
			//MYINFO("Inside %s Address of %s: %08x" ,IMG_Name(img).c_str(),func_name, va_address);
			
			RTN_Open(rtn);
			// different arguments get passed to the hooking routine depending on the specific function
			switch(index){
				case(VIRTUALFREE_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)VirtualFreeHook,
										IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpAddress for VirtualFree
										IARG_END);
					break;
				case(CREATEPROCESS_INDEX):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CreateProcessHookEntry,
										IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpCommandLine? TODO check this
										IARG_END);
					break;

				/*
				case(VIRTUALALLOC_INDEX):
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAllocHook,
										IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // SIZE_T dwSize
										IARG_FUNCRET_EXITPOINT_VALUE,
										IARG_END);
					break;
				case(RTLALLOCATEHEAP_INDEX):
					//need to be IPOINT_AFTER because the allocated address is returned as return value
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)RtlAllocateHeapHook,
										IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // SIZE_T Size
										IARG_FUNCRET_EXITPOINT_VALUE,
										IARG_END);
					break;
				case(ISDEBUGGERPRESENT_INDEX):
					RTN_Replace(rtn, AFUNPTR(IsDebuggerPresentHook));
					break;
				case(RTLREALLOCATEHEAP_INDEX):
					//IPOINT_BEFORE because the address to be realloc is passed as an input paramenter
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)RtlReAllocateHeapHook,
										IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // MemoryPointer
										IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // Size
										IARG_END);
					break;
				*/
				}			
			RTN_Close(rtn);
		}
	}
}


