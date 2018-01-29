#include "ProcInfo.h"
#include "porting.h"
#include "math.h"

#include <algorithm>

// singleton
ProcInfo* ProcInfo::instance = 0;

ProcInfo* ProcInfo::getInstance()
{
	if (instance == 0)
		instance = new ProcInfo();
		
	return instance;
}

ProcInfo::ProcInfo()
{
	this->prev_ip = 0;
	this->popad_flag = FALSE;
	this->pushad_flag = FALSE;
	this->start_timer = -1;
}

ProcInfo::~ProcInfo(void)
{
}

/* ----------------------------- SETTER -----------------------------*/

void ProcInfo::setFirstINSaddress(ADDRINT address){
	this->first_instruction  = address;
}

void ProcInfo::setPrevIp(ADDRINT ip){
	this->prev_ip  = ip;
}

void ProcInfo::setPushadFlag(BOOL flag){
	this->pushad_flag = flag;
}


void ProcInfo::setPopadFlag(BOOL flag){
	this->popad_flag = flag;
}

void ProcInfo::setProcName(string name){
	this->full_proc_name = name;
	//get the starting position of the last element of the path (the exe name)
	size_t pos_exe_name = name.find_last_of("\\");
	string exe_name = name.substr(pos_exe_name + 1);
	//get the name from the last occurrence of / till the end of the string minus the file extension
	exe_name = Helper::replaceString(exe_name, " ", "");
	this->proc_name =  exe_name.substr(0, exe_name.length() - 4);
}

void ProcInfo::setInitialEntropy(float Entropy){
	this->InitialEntropy = Entropy;
}

void ProcInfo::setStartTimer(clock_t t){
	this->start_timer = t;
}


/* ----------------------------- GETTER -----------------------------*/


ADDRINT ProcInfo::getFirstINSaddress(){
	return this->first_instruction;
}

ADDRINT ProcInfo::getPrevIp(){
	return this->prev_ip;
}

std::vector<Section> ProcInfo::getSections(){
	return this->Sections;
}

std::vector<Section> ProcInfo::getProtectedSections(){
	return this->protected_section;
}

BOOL ProcInfo::getPushadFlag(){
	return this->pushad_flag ;
}

BOOL ProcInfo::getPopadFlag(){
	return this->popad_flag;
}

string ProcInfo::getProcName(){
	return this->proc_name;
}

float ProcInfo::getInitialEntropy(){
	return this->InitialEntropy;
}

std::set<ADDRINT> ProcInfo::getJmpBlacklist(){ /* DCD: unordered_set */
	return this->addr_jmp_blacklist;
}

clock_t ProcInfo::getStartTimer(){
	return this->start_timer;
}

std::map<string , HeapZone> ProcInfo::getHeapMap(){
	return this->HeapMap;
}

std::map<string,string> ProcInfo::getDumpedHZ(){
	return this->HeapMapDumped;

}

/* ----------------------------- UTILS -----------------------------*/

// print the sections information in a fancy way
void ProcInfo::PrintSections(){
	MYINFO("======= SECTIONS ======= \n");
	for(unsigned int i = 0; i < this->Sections.size(); i++) {
		Section item = this->Sections.at(i);
		MYINFO("%s	->	begin : %08x		end : %08x", item.name.c_str(), item.begin, item.end);
	}
	MYINFO("================================= \n");
}

//insert a new section in our structure
void ProcInfo::insertSection(Section section){
	this->Sections.push_back(section);
}

//return the section's name where the IP resides
string ProcInfo::getSectionNameByIp(ADDRINT ip){
	string s = "";
	for(unsigned int i = 0; i < this->Sections.size(); i++) {
		Section item = this->Sections.at(i);
		if(ip >= item.begin && ip <= item.end){
			s = item.name;
		}
	}
	return s;
}

// insert the mmory range in the current list of memory ranges detected on the heap
void ProcInfo::insertHeapZone(std::string hz_md5,HeapZone heap_zone){
	this->HeapMap.insert( std::pair<std::string,HeapZone>(hz_md5,heap_zone) );
}

void ProcInfo::insertDumpedHeapZone(std::string hz_data_md5, std::string hz_bin_path){
	this->HeapMapDumped.insert( std::pair<std::string,std::string>(hz_data_md5,hz_bin_path) );
}


// remove a specific memory range from the heap list
void ProcInfo::deleteHeapZone(std::string md5_to_remove){     
	this->HeapMap.erase(md5_to_remove);
}

// return the index of the memory range that includes the specified address
// if it is not found it returns -1
bool ProcInfo::searchHeapMap(ADDRINT ip){
	int i=0;
	HeapZone hz;

	if(  ip== 0x01600118  ){
		MYINFO("Now checking if the address is inside the heapmap");
	}

	for (std::map<std::string,HeapZone>::iterator it=HeapMap.begin(); it!=HeapMap.end(); ++it){	
		hz = it->second;
		if(  ip== 0x01600118  ){
			MYINFO("-----------Checking hz.begin= %08x - hz.end = %08x\n", hz.begin, hz.end);
		}
		if(ip >= hz.begin && ip <= hz.end){
if(  ip== 0x01600118  ){
	MYINFO("Well, true for %08x %08x", hz.begin, hz.end);}
			   return true;
		}
	}

	if(  ip== 0x01600118  ){
		MYINFO("%08x isn't in any range\n", ip);}
	return false;
}


//return the entropy value of the entire program
float ProcInfo::GetEntropy(){
	IMG binary_image = APP_ImgHead();
	// trick in order to convert a ln in log2
	const double d1log2 = 1.4426950408889634073599246810023;
	double Entropy = 0.0;
	unsigned long Entries[256];
	unsigned char* Buffer;
	//calculate the entropy only on the main module address space
	ADDRINT start_address = IMG_LowAddress(binary_image);
	ADDRINT end_address = IMG_HighAddress(binary_image);
	UINT32 size = S_ADDR_DIFF(start_address, end_address);
	// copy the main module in a buffer in order to analyze it
	Buffer = (unsigned char *)malloc(size);
	PIN_SafeCopy(Buffer , (void const *)start_address , size);
	// set to all zero the matrix of the bytes occurrence
	memset(Entries, 0, sizeof(unsigned long) * 256);
	// increment the counter of the current read byte (Buffer[i])in the occurence matrix (Entries)
	for (size_t i = 0; i < size; i++)
		Entries[Buffer[i]]++;
	// do the shannon formula on the occurence matrix ( H = sum(P(i)*log2(P(i)) )
	for (size_t i = 0; i < 256; i++) {
		double Temp = (double) Entries[i] / (double) size;
		if (Temp > 0)
			Entropy += -Temp*(log(Temp)*d1log2);
	}
	return (float)Entropy; // this cast should be just fine!
}

// 
void ProcInfo::insertInJmpBlacklist(ADDRINT ip){
	this->addr_jmp_blacklist.insert(ip);
}

BOOL ProcInfo::isInsideJmpBlacklist(ADDRINT ip){
	return this->addr_jmp_blacklist.find(ip) != this->addr_jmp_blacklist.end();
}



void ProcInfo::printHeapList(){
		
	int cont = 1;
	for (std::map<std::string,HeapZone>::iterator it=HeapMap.begin(); it!=HeapMap.end(); ++it){	
		HeapZone hz = it->second;
		MYINFO("Heapzone number  %u  start %08x end %08x",cont,hz.begin,hz.end);
		cont++;
	}
}


BOOL ProcInfo::isInsideMainIMG(ADDRINT address){
	return mainImg.StartAddress <= address && address <= mainImg.EndAddress;
}

VOID ProcInfo::setMainIMGAddress(ADDRINT startAddr,ADDRINT endAddr){
	mainImg.StartAddress = startAddr;
	mainImg.EndAddress = endAddr;
}



//+++++++++++++++++++++++++++++++++++++++++++++++++++++++ Memory layout information +++++++++++++++++++++++++++++++++++++++++++++++++++++++

//--------------------------------------------------Library--------------------------------------------------------------

BOOL ProcInfo::isLibItemDuplicate(ADDRINT address , std::vector<LibraryItem> Libraries ){
	for(std::vector<LibraryItem>::iterator lib =  Libraries.begin(); lib != Libraries.end(); ++lib) {
		if ( address == lib->StartAddress ){
		return TRUE;
		}
	}
	return FALSE;
}

/**
add library in a list sorted by address
**/
VOID ProcInfo::addLibrary(const string name,ADDRINT startAddr,ADDRINT endAddr){
	LibraryItem libItem;
	libItem.StartAddress = startAddr;
	libItem.EndAddress = endAddr;
	libItem.name = name;
	if(isKnownLibrary(name,startAddr,endAddr)){		
		//check if the library is present yet in the list of knownLibraries
	    if(!isLibItemDuplicate(startAddr , knownLibraries)){
			knownLibraries.push_back(libItem);
		}
		return;	
	}
	else{
		//check if the library is present yet in the list of unknownLibraries
		if(!isLibItemDuplicate(startAddr , unknownLibraries)){
			unknownLibraries.push_back(libItem);
		}
		return;
	}
}


/**
Convert a LibraryItem object to string
**/
string ProcInfo::libToString(LibraryItem lib){
	std::stringstream ss;
	ss << "Library: " <<lib.name;
	ss << "\t\tstart: " << std::hex << lib.StartAddress;
	ss << "\tend: " << std::hex << lib.EndAddress;
	const std::string s = ss.str();	
	return s;	
}


/**
Check the current name against a set of whitelisted library names
(IDEA don't track kernel32.dll ... but track custom dll which may contain malicious payloads)
**/
BOOL ProcInfo::isKnownLibrary(const string name, ADDRINT startAddr, ADDRINT endAddr){	
	char* lcName = strdup(name.c_str());
	size_t len = strlen(lcName);
	for (size_t i = 0; i < len; ++i) {
		lcName[i] = tolower(lcName[i]);
	}	
	// use lowercase for earch
	BOOL isSystemDll = !strstr(lcName, "c:\\windows\\system32");
	isSystemDll = isSystemDll || !strstr(lcName, "c:\\windows\\syswow64");
	free(lcName);

	//MYINFO("Dll Name %s is system %d", name.c_str(), isSystemDll);
	if (isSystemDll) {
		return TRUE;
	} else {
		MYINFO("Found Unknown library %s from %08x  to   %08x: start tracking its instruction\n",name.c_str(),startAddr,endAddr);
		return FALSE;
	}
}

/*check if the address belong to a Library */
//TODO add a whiitelist of safe Windows libraries that will be loaded
BOOL ProcInfo::isLibraryInstruction(ADDRINT address){	 
	//check inside known libraries
	for(std::vector<LibraryItem>::iterator lib = knownLibraries.begin(); lib != knownLibraries.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress){
		return TRUE;}
	}
	//check inside unknown libraries
	for(std::vector<LibraryItem>::iterator lib = unknownLibraries.begin(); lib != unknownLibraries.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress){
			return TRUE;   
		}
	}
	return FALSE;	
}

BOOL ProcInfo::isKnownLibraryInstruction(ADDRINT address){
	//check inside known libraries
	for(std::vector<LibraryItem>::iterator lib = knownLibraries.begin(); lib != knownLibraries.end(); ++lib) {
		if (lib->StartAddress <= address && address <= lib->EndAddress)
			return TRUE;
	}
	return FALSE;	
}

// bootstrap memory information
void ProcInfo::addProcAddresses(){
	setCurrentMappedFiles();
	addPebAddress();
	// process addresses from PEB to get their memory ranges
	addContextDataAddress(); // peb->{ActivationContextData, SystemDefaultActivationContextData, pContextData}
	addAnsiCodePageDataAddress();
	addSharedMemoryAddress();
	addProcessHeapsAndCheckAddress(NULL);
	addShimDataAddress();
	addApiSetMapAddress();
	addKUserSharedDataAddress();
}

//------------------------------------------------------------PEB------------------------------------------------------------

VOID ProcInfo::addPebAddress(){
	// invoke ZwQueryInformationProcess via GetProcAddress to get PEB info
	typedef int (WINAPI* ZwQueryInformationProcess)(W::HANDLE,W::DWORD,W::PROCESS_BASIC_INFORMATION*,W::DWORD,W::DWORD*);
	ZwQueryInformationProcess MyZwQueryInformationProcess; 
	W::PROCESS_BASIC_INFORMATION tmppeb;
	W::DWORD tmp; 
	W::HMODULE hMod = W::GetModuleHandle("ntdll.dll");
	MyZwQueryInformationProcess = (ZwQueryInformationProcess)W::GetProcAddress(hMod,"ZwQueryInformationProcess"); 
	MyZwQueryInformationProcess(W::GetCurrentProcess(),
								0,
								&tmppeb,
								sizeof(W::PROCESS_BASIC_INFORMATION),
								&tmp);
	peb = (PEB *) tmppeb.PebBaseAddress;
	MYINFO("PEB added from %08x -> %08x", peb, peb+sizeof(PEB));
}

BOOL ProcInfo::isPebAddress(ADDRINT addr) {
	return ((ADDRINT)peb <= addr && addr <= (ADDRINT)peb + sizeof(PEB) ) ;
} 

//------------------------------------------------------------TEB------------------------------------------------------------

//Check if an address in on the Teb
BOOL ProcInfo::isTebAddress(ADDRINT addr) {
	for(std::vector<MemoryRange>::iterator it = tebs.begin(); it != tebs.end(); ++it){
		if(it->StartAddress <= addr && addr <= it->EndAddress){
			return TRUE;
		}
	}
	return FALSE;
}

VOID ProcInfo::addThreadTebAddress(){
	W::_TEB *tebAddr = W::NtCurrentTeb();
	MemoryRange cur_teb;
	cur_teb.StartAddress = (ADDRINT)tebAddr;
	cur_teb.EndAddress = (ADDRINT)tebAddr +TEB_SIZE;
	tebs.push_back(cur_teb);
}


//------------------------------------------------------------ Stack ------------------------------------------------------------

/**
Check if an address in on the stack
**/
BOOL ProcInfo::isStackAddress(ADDRINT addr) {
	for(std::vector<MemoryRange>::iterator it = stacks.begin(); it != stacks.end(); ++it){
		if(it->StartAddress <= addr && addr <= it->EndAddress){
			return TRUE;
		}
	}
	return FALSE;
}

/**
Initializing the base stack address by getting a value in the stack and searching the highest allocated address in the same memory region
**/
VOID ProcInfo::addThreadStackAddress(ADDRINT addr){
	//hasn't been already initialized
	MemoryRange stack;
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes = W::VirtualQuery((W::LPCVOID)addr, &mbi, sizeof(mbi));
	//get the stack base address by searching the highest address in the allocated memory containing the stack Address
	if(mbi.State == MEM_COMMIT || mbi.Type == MEM_PRIVATE ){
		stack.EndAddress = (int)mbi.BaseAddress+ mbi.RegionSize;
	}
	else{
		stack.EndAddress = addr;
	}
	//check integer underflow ADDRINT
	if(stack.EndAddress <= MAX_STACK_SIZE ){
		stack.StartAddress =0;
	}
	else{
		stack.StartAddress = stack.EndAddress - MAX_STACK_SIZE;
	}
	MYINFO("Init Stacks by adding from %x to %x",stack.StartAddress,stack.EndAddress);
	stacks.push_back(stack);
}

/**
Fill the MemoryRange passed as parameter with startAddress and endAddress
of the memory region to which the address belongs.
ADDRINT address:  address of which we want to retrieve the memory region
MemoryRange& range: ref to MemoryRange object to fill
return TRUE if the address belongs to a memory mapped area otherwise return FALSE
**/
BOOL ProcInfo::getMemoryRange(ADDRINT address, MemoryRange& range){		
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes = W::VirtualQuery((W::LPCVOID)address, &mbi, sizeof(mbi));
	if(numBytes == 0){
		MYERRORE("VirtualQuery failed");
		return FALSE;
	}
	ADDRINT start = (ADDRINT)mbi.BaseAddress;
	ADDRINT end = (ADDRINT)mbi.BaseAddress + mbi.RegionSize;


	//get the stack base address by searching the highest address in the allocated memory containing the stack Address
	if (start <= address && address <= end && (mbi.State == MEM_COMMIT || mbi.Type == MEM_MAPPED ||
											   mbi.Type == MEM_IMAGE ||  mbi.Type == MEM_PRIVATE)) {
		range.StartAddress = start;
		range.EndAddress = end;
		return TRUE;
	}
	else{
		/* TODO check this from calc.exe run */
		MYERRORE("Address %08x  not inside mapped memory from %08x -> %08x or Type/State not correct ",address,start,end);
		MYINFO("state %08x   %08x",mbi.State,mbi.Type);
		return  FALSE;
	}		
}

// helper method for common operations involving getMemoryRange()
inline void ProcInfo::addMemoryRange(ADDRINT address, std::vector<MemoryRange> &container, const char* nameForLog) {
	MemoryRange range;
	if (getMemoryRange(address, range)) {
		if (nameForLog) MYINFO("%s base address %08x -> %08x", nameForLog, range.StartAddress, range.EndAddress);
		container.push_back(range);
	}
}




//------------------------ Protected sections (Functions for FakeWriteHandler) --------------------//

/*
	Add a section of a module ( for example the .text of the NTDLL ) in order to catch
	writes/reads inside this area
*/
VOID ProcInfo::addProtectedSection(ADDRINT startAddr, ADDRINT endAddr){
	Section s;
	s.begin = startAddr;
	s.end = endAddr;
	s.name = ".text";
	
	MYINFO("Protected section size is %d\n" , this->protected_section.size());
	protected_section.push_back(s);
	MYINFO("Added to protected section NTDLL %08x %08x\n" , startAddr,endAddr);
	MYINFO("Protected section size is %d\n" , this->protected_section.size());
}

/*
	Check if an address is inside a protected section 
*/
BOOL ProcInfo::isInsideProtectedSection(ADDRINT address){
	for(std::vector<Section>::iterator it = protected_section.begin(); it != protected_section.end(); ++it){
		
		if(it->begin <= address && address <= it->end){
			//MYINFO("Detected  %08x is inside %08x %08x",address, it->begin,it->end);
			
			return TRUE;
		}
	}
	return FALSE;
}


//----------------------------- Know memory regions to whitelist(Functions for FakeMemoryReader) -------------

//------------------------------------------------------------ Memory Mapped Files------------------------------------------------------------

//Add to the mapped files list the region marked as mapped when the application starts
VOID ProcInfo::setCurrentMappedFiles(){
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	ADDRINT MyAddress = 0;	
	mappedFiles.clear(); // delete old entries

	/* TODO - PinCRT lacks proper documentation for the 'type' field,
	 * perhaps we can reverse-engineer it using sample programs */
	//NATIVE_PID curPid;
	//OS_GetPid(&curPid);
	//OS_MEMORY_AT_ADDR_INFORMATION info;
	//void* address = NULL;

	/* DCD: VirtualQuery behaves differently under Pin 3.5? */
	W::PVOID maxAddr = 0;
	while (1) {
		//OS_QueryMemory(curPid, address, &info);
		numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi));
		
		// workaround for not getting stuck on the last valid block (see above)
		if (maxAddr && maxAddr >= mbi.BaseAddress) break;
		maxAddr = mbi.BaseAddress;
		//std::cerr << std::hex << to_string(mbi.BaseAddress) << " " << to_string(mbi.RegionSize) << std::endl;
		
		if (mbi.Type == MEM_MAPPED){
			MemoryRange range;
			range.StartAddress = (ADDRINT)mbi.BaseAddress;
			range.EndAddress = (ADDRINT)mbi.BaseAddress + mbi.RegionSize;
			mappedFiles.push_back(range);
		}
		MyAddress += mbi.RegionSize;
	}
}

BOOL ProcInfo::isMappedFileAddress(ADDRINT addr){
	for(std::vector<MemoryRange>::iterator item = mappedFiles.begin(); item != mappedFiles.end(); ++item) {
		if(item->StartAddress <= addr && addr <= item->EndAddress){
			return true;
		}			
	}
	return false;
}

VOID  ProcInfo::printMappedFileAddress(){
	for(std::vector<MemoryRange>::iterator item = mappedFiles.begin(); item != mappedFiles.end(); ++item) {
		MYINFO("Mapped file %08x -> %08x ",item->StartAddress , item->EndAddress);
	}
}

//Add dynamically created mapped files to the mapped files list
VOID ProcInfo::addMappedFilesAddress(ADDRINT startAddr){
	addMemoryRange(startAddr, mappedFiles, "Add mappedFile");
}


//------------------------------------------------------------ Other Memory Location ------------------------------------------------------------

BOOL ProcInfo::isGenericMemoryAddress(ADDRINT address){
	for(std::vector<MemoryRange>::iterator item = genericMemoryRanges.begin(); item != genericMemoryRanges.end(); ++item) {
		if(item->StartAddress <= address && address <= item->EndAddress){
			return true;
		}			
	}
	return false;
}

//Adding the ContextData to the generic Memory Ranges
inline VOID ProcInfo::addContextDataAddress(){
	addMemoryRange((ADDRINT)peb->ActivationContextData, genericMemoryRanges, "Init activationContextData");
	addMemoryRange((ADDRINT)peb->SystemDefaultActivationContextData, genericMemoryRanges, "Init systemDefaultActivationContextData");
	addMemoryRange((ADDRINT)peb->pContextData, genericMemoryRanges, "Init pContextData");
}

//Adding the SharedMemoryAddress to the generic Memory Ranges
inline VOID ProcInfo::addSharedMemoryAddress(){
	addMemoryRange((ADDRINT)peb->ReadOnlySharedMemoryBase, genericMemoryRanges, "Init readOnlySharedMemoryBase");
}

//Adding the CodePageDataAddress to the generic Memory Ranges
inline VOID ProcInfo::addAnsiCodePageDataAddress(){
	addMemoryRange((ADDRINT)peb->AnsiCodePageData, genericMemoryRanges, "Init ansiCodePageData");
}

//Adding the pShimDataAddress to the generic Memory Ranges
inline VOID ProcInfo::addShimDataAddress(){
	addMemoryRange((ADDRINT)peb->pShimData, genericMemoryRanges, "Init pShimData");
}

//Adding the ApiSetMapAddress to the generic Memory Ranges
inline VOID ProcInfo::addApiSetMapAddress(){
	addMemoryRange((ADDRINT)peb->ApiSetMap, genericMemoryRanges, "Init ApiSetMap");
}

//Add to the generic memory ranges the KUserShareData structure
VOID ProcInfo::addKUserSharedDataAddress(){
	MemoryRange KUserSharedData;
	KUserSharedData.StartAddress = KUSER_SHARED_DATA_ADDRESS;
	KUserSharedData.EndAddress = KUSER_SHARED_DATA_ADDRESS + KUSER_SHARED_DATA_SIZE;
	genericMemoryRanges.push_back(KUserSharedData);
}

//Adding the ProcessHeaps to the generic Memory Ranges
BOOL ProcInfo::addProcessHeapsAndCheckAddress(ADDRINT eip){
	BOOL isEipDiscoveredHere = FALSE;
	W::SIZE_T BytesToAllocate;
	W::PHANDLE aHeaps;
	//getting the number of ProcessHeaps
	W::DWORD NumberOfHeaps = W::GetProcessHeaps(0, NULL);
    if (NumberOfHeaps == 0) {
		MYERRORE("Error in retrieving number of Process Heaps");
		return isEipDiscoveredHere;
	}
	//Allocating space for the ProcessHeaps Addresses
	W::SIZETMult(NumberOfHeaps, sizeof(*aHeaps), &BytesToAllocate);
	aHeaps = (W::PHANDLE)W::HeapAlloc(W::GetProcessHeap(), 0, BytesToAllocate);
	 if ( aHeaps == NULL) {
		MYERRORE("HeapAlloc failed to allocate space");
		return isEipDiscoveredHere;
	} 

	W::GetProcessHeaps(NumberOfHeaps,aHeaps);
	//Adding the memory range containing the ProcessHeaps to the  genericMemoryRanges
	 for (size_t i = 0; i < NumberOfHeaps; ++i) {
		MemoryRange processHeap;
		if(getMemoryRange((ADDRINT) aHeaps[i],processHeap)){
			genericMemoryRanges.push_back(processHeap);
			if(eip >= processHeap.StartAddress && eip <= processHeap.EndAddress){
				isEipDiscoveredHere = TRUE;
			}
		}
    }
	return isEipDiscoveredHere;
}


//-------------------------- Anti process fingerprint --------------
BOOL ProcInfo::isInterestingProcess(unsigned int pid){
	return this->interresting_processes_pid.find(pid) != this->interresting_processes_pid.end();
}

// print the whitelisted memory in a fancy way
void ProcInfo::PrintWhiteListedAddr(){
	//Iterate through the already whitelisted memory addresses
	for(std::vector<MemoryRange>::iterator item = genericMemoryRanges.begin(); item != genericMemoryRanges.end(); ++item) {
		MYINFO("[MEMORY RANGE]Whitelisted  %08x  ->  %08x\n",item->StartAddress,item->EndAddress);				
	}
	for (std::map<std::string,HeapZone>::iterator it=HeapMap.begin(); it!=HeapMap.end(); ++it){	
		HeapZone hz = it->second;
		MYINFO("[HEAPZONES]Whitelisted  %08x  ->  %08x\n",hz.begin,hz.end);				
	}
	for(std::vector<LibraryItem>::iterator item = this->unknownLibraries.begin(); item != this->unknownLibraries.end(); ++item) {
		MYINFO("[UNKNOWN LIBRARY ITEM]Whitelisted  %08x  ->  %08x\n",item->StartAddress,item->EndAddress);				
	}
	for(std::vector<LibraryItem>::iterator item = this->knownLibraries.begin(); item != this->knownLibraries.end(); ++item) {
		MYINFO("[KNOWN LIBRARY ITEM]Whitelisted  %08x  ->  %08x\n",item->StartAddress,item->EndAddress);				
	}
	for(std::vector<MemoryRange>::iterator item = this->mappedFiles.begin(); item != this->mappedFiles.end(); ++item) {
		MYINFO("[MAPPED FILES]Whitelisted  %08x  ->  %08x\n",item->StartAddress,item->EndAddress);				
	}
}