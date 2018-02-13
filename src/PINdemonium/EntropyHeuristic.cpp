#include "EntropyHeuristic.h"

#define ENTROPY_THRESHOLD	0.2f

int EntropyHeuristic::run(){
	ProcInfo *proc_info = ProcInfo::getInstance();
	float entropy_value = proc_info->GetEntropy();
	float initial_entropy = proc_info->getInitialEntropy();
	float difference = std::abs(entropy_value - initial_entropy)/initial_entropy;
	
	MYINFO("INITIAL ENTROPY IS %f" , initial_entropy);
	MYINFO("CURRENT ENTROPY IS %f" , entropy_value);
	MYINFO("ENTROPY DIFFERERNCE IS %f" , difference);
	
	bool result = (difference > ENTROPY_THRESHOLD);

	/* TODO: as of now Pin would need an ad-hoc internal exception handler */
	//try{
	ReportDump& report_dump = Report::getInstance()->getCurrentDump();
	ReportObject* entropy_heur = new ReportEntropy(result,entropy_value,difference);
	report_dump.addHeuristic(entropy_heur);
	//}catch (const std::out_of_range&){
	//		MYERROR("Problem creating ReportEntropy report");
	//}

	if (result){
		return OepFinder::FOUND_OEP;
	}
	else return OepFinder::HEURISTIC_FAIL;
}




