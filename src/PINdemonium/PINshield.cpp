#include "PINshield.h"
//#include <regex> /* TODO */

#define KUSER_SHARED_DATA_ADDRESS 0x7ffe0000
#define KUSER_SHARED_DATA_SIZE 0x3e0 

// called by the main procedure for INS_AddInstrumentFunction()
void PINshield::addInstrumentation(INS ins) {
	ADDRINT addr = INS_Address(ins);
	ProcInfo *pInfo = ProcInfo::getInstance();
	Config *config = Config::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();

	// skip instructions from a known library (say graphic DLL)
	if (filterHandler->isFilteredLibraryInstruction(addr)) {
		return;
	}

	// 1 - single instruction detection
	if (config->ANTIEVASION_MODE_INS_PATCHING && this->evasionPatcher.patchDispatcher(ins, addr)) {
		return;
	}

	// 2 - check for memory reads at addresses that the application should not be aware of
	if (config->ANTIEVASION_MODE_SREAD) {
		for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
			if (INS_MemoryOperandIsRead(ins, op)) {
				// initialize FakeReadHandler on the first read we ever see
				if (!isFakeReadInitialized) {
					fakeReadH.initFakeMemory();
					isFakeReadInitialized = true;
				}
				// get a scratch register
				REG scratchReg = GetScratchReg(op);
				// call handleRead() before ins gets executed
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(handleRead),
					IARG_INST_PTR, // pass address of instrumented instruction as first argument
					IARG_MEMORYOP_EA, op,
					IARG_PTR, &fakeReadH,
					IARG_RETURN_REGS, scratchReg,
					IARG_END);
				// make the read reference the scratchReg returned by handleRead()
				INS_RewriteMemoryOperand(ins, op, scratchReg);
			}
		}
	}

	// 3 - check for memory reads at addresses that the application should not be access
	if (config->ANTIEVASION_MODE_SWRITE) {
		for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) {
			if (INS_MemoryOperandIsWritten(ins, op) && INS_IsMov(ins)) {
				REG writeReg = GetScratchReg(op);
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(handleWrite),
					IARG_INST_PTR, // pass address of instrumented instruction as first argument
					IARG_MEMORYOP_EA, op,
					IARG_PTR, &fakeWriteH,
					IARG_RETURN_REGS, writeReg,
					IARG_END);
				INS_RewriteMemoryOperand(ins, op, writeReg);
			}
		}
	}
}

ADDRINT handleRead(ADDRINT eip, ADDRINT read_addr, void *fake_mem_h){
	FakeReadHandler* theFakeReadH = (FakeReadHandler*)fake_mem_h;
	ADDRINT fakeAddr = theFakeReadH->getFakeMemory(read_addr, eip);
	
	// the function invoked by the FakeReadHandler may return a NULL address 
	if (fakeAddr == NULL){
		MYINFO("%08x in %s reading %08x",eip, RTN_FindNameByAddress(eip).c_str(), read_addr);
	}
	
	if (read_addr == 0){
		return read_addr; // let the program trigger an exception if it wants
	}

	if (fakeAddr != read_addr){
		/*
		if(read_addr < KUSER_SHARED_DATA_ADDRESS  || read_addr > KUSER_SHARED_DATA_ADDRESS + KUSER_SHARED_DATA_SIZE){
			MYINFO("handleRead_evasion %08x read at %08x",eip,read_addr);
		}
		*/

		MYTEST("[POSSIBLE EVASIVE BEHAVIOR] Read inside a protected memory region\n");
		//MYINFO("ip : %08x in %s reading %08x and it has been redirected to : %08x",eip, RTN_FindNameByAddress(eip).c_str() , read_addr, fake_addr);
	}
	return fakeAddr;
}

ADDRINT handleWrite(ADDRINT eip, ADDRINT write_addr, void *fakeWriteH){	
	
	FakeWriteHandler* theFakeWriteH = (FakeWriteHandler *)fakeWriteH;
	//get the new address of the memory operand (same as before if it is inside the whitelist otherwise a NULL poiter)
	ADDRINT fakeAddr = theFakeWriteH->getFakeWriteAddress(write_addr);
	
	if (write_addr == NULL) {
		return write_addr; // let the program trigger an exception if it wants
	}
	
	if (fakeAddr != write_addr) {
		MYTEST("[POSSIBLE EVASIVE BEHAVIOR] Detected write on protected memory region ( f.i. NTDLL .text )\n");
		/*
		MYTEST("handleWrite_evasion %08x",write_addr);
		MYINFO("suspicious write from %08x in %s in %08x redirected to %08x", eip, RTN_FindNameByAddress(write_addr).c_str(), write_addr, fakeAddr);
		MYINFO("Binary writes %08x\n" , *(unsigned int *)(fakeAddr));
		*/
	}
	return fakeAddr;
}

//get the first scratch register available
//we build a vector in order to deal with multiple read operands
static REG GetScratchReg(UINT32 index)
{
    static std::vector<REG> regs;
    while (index >= regs.size()) {
		//get the first clean register
        REG reg = PIN_ClaimToolRegister();
        regs.push_back(reg);
    }
    return regs[index];
}

/* This is a leftover
// In order to avoid obsidium to take the path of the 'or byte ptr [esp+0x1],0x1' 
VOID KillObsidiumDeadPath(CONTEXT *ctxt){
	PIN_SetContextReg(ctxt,REG_EAX,0x7);
}
*/
