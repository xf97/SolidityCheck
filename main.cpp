#include <iostream>
#include "ArrangeCode.h"
#include "FileBackup.h"
#include "Reentrant.h"
#include "PriModifier.h"
#include "CostlyLoop.h"
#include "BalanceEquality.h"
#include "UncheckedCall.h"
#include "TxOrigin.h"
#include "TypeInference.h"
#include "VersionNum.h"
#include "Send.h"
#include "Random.h"
#include "TimeDepend.h"
#include "ReportGenerator.h"
#include "InsertCode.h"
#include "MaliciousLib.h"
#include "AddressFixed.h"
#include "IntDivision.h"
#include "LockedMoney.h"
#include "ByteArray.h"
#include "RedFallback.h"
#include "IrregularStyle.h"
#include "VisibilityLevel.h"
#include "FixedFloat.h"
#include "AllGas.h"
#include "ERC20Conflict.h"
#include "Overflow.h"
#include "DosExternal.h"
#include "MissConstructor.h"
#include <iomanip>
#include "Selfdestruct.h"


void OutHelp() {
	cout << "SolidityCheck --help\tget help information\n";
	cout << "SolidityCheck --r\tCheck for reentry vulnerabilities and generate stub files for test reentrany\n";
	cout << "SolidityCheck --o\tCheck integer overflow and generate stub files to prevent integer overflow\n";
	cout << "SolidityCheck --d\tScanning the contract thoroughly to check all problems except reentrancy and integer overflow\n";
	cout << "SolidityCheck --g\tGet current gas limits for costly loop\n";
	cout << "SolidityCheck --s\tSet current gas limits for costly loop\n";
	cout << "SolidityCheck --f\tBatch inspection\n";
	return;
}

bool exist(const string filename) {
	string temp = filename;
	temp = temp.substr(0, temp.size() - 4);
	temp += "_detect.report";
	ifstream inFile(temp.c_str());
	if (inFile.is_open()) {
		inFile.close();
		return true;
	}
	else {
		inFile.close();
		return false;
	}
}

void Detection_F() {
	cout << "enter the file of contracts' name: ";
	string filename;
	cin >> filename;
	ifstream inFile(filename.c_str());
	if (!inFile.is_open()) {
		cout << "Could not open file.\n";
		return;
	}
	string temp;
	Time t;
	t.startTime();
	int i = 1;
	while (getline(inFile, temp)) {
		cout << "count: " << (i++) << endl;
		/*
		//判断该合约的检测报告是否已经存在
		if (exist(temp)) {
			continue;
		}*/
			FileIO io(temp);
			//1.get file content
			io.ReadIn();
			//2.formatting file content
			ArrangeCode ar(io.OutString(), io.outFileName());
			ar.FormatCode();
			ar.StrToVec(ar.OutOldString());
			io.OutToFile(ar.OutNewName(), ar.VecToStr(ar.OutVec()));
			Output ot(io.outFileName(), ar.OutReport(), io.GetRows());
			//3.backup formatting content
			FileBackup fb(ar.OutOldName(), ar.OutVec());
			fb.OutBackFile();
			//4.detection of vulnerabilities
		//4.1 Private Modifier
			cout << "-----Start detecting-----\n";
			cout << "0%[->........................]";
			PriModifier pr(ar.OutReport(), ar.OutVec());
			pr.Detection();
			ot.AddString(pr.MakeReport(pr.GetRowNumber()));
			ot.AddNumber(pr.GetNumber());
			cout << "\r4%[*->.......................]";
			//4.2 Costly Loop
			Match ma;
			CostlyLoop cl(ar.OutReport(), ar.OutVec());
			cl.Detection(ma);
			ot.AddString(cl.MakeReport(cl.GetRowNumber()));
			ot.AddNumber(cl.GetNumber());
			cout << "\r8%[**->......................]";
			//4.3 Balance equality
			Balance be(ar.OutReport(), ar.OutVec());
			//be.Detection();
			be.Re_Detection();
			ot.AddString(be.MakeReport(be.GetRowNumber()));
			ot.AddNumber(be.GetNumber());
			cout << "\r12%[***->.....................]";
			//4.4 Unchecked external call
			Call uc(ar.OutReport(), ar.OutVec());
			//uc.Detection();
			uc.Re_Detection();
			ot.AddString(uc.MakeReport(uc.GetRowNumber()));
			ot.AddNumber(uc.GetNumber());
			cout << "\r16%[****->....................]";
			//4.5 Using Tx.origin
			TxOrigin tx(ar.OutReport(), ar.OutVec());
			//tx.Detection();
			tx.Re_Detection();
			ot.AddString(tx.MakeReport(tx.GetRowNumber()));
			ot.AddNumber(tx.GetNumber());
			cout << "\r20%[*****->...................]";
			//4.6 Unsafe type inference
			TypeInfer ti(ar.OutReport(), ar.OutVec());
			//ti.Detection();
			ti.Re_Detection();
			ot.AddString(ti.MakeReport(ti.GetRowNumber()));
			ot.AddNumber(ti.GetNumber());
			cout << "\r24%[******->..................]";
			//4.7 Detect complier version
			VersionNum vn(ar.OutReport(), ar.OutVec());
			//vn.Detection();
			vn.Re_Detection();
			ot.AddString(vn.MakeReport(vn.GetRowNumber()));
			ot.AddNumber(vn.GetNumber());
			cout << "\r28%[*******->.................]";
			//4.8 Detect send instead of transfer
			Send se(ar.OutReport(), ar.OutVec());
			//se.Detection();
			se.Re_Detection();
			ot.AddString(se.MakeReport(se.GetRowNumber()));
			ot.AddNumber(se.GetNumber());
			cout << "\r32%[********->................]";
			//4.9 Using random numbers
			//RA_Match rma;
			Random ra(ar.OutReport(), ar.OutVec());
			//ra.Detection(rma);
			ra.Re_Detection();
			ot.AddString(ra.MakeReport(ra.GetRowNumber()));
			ot.AddNumber(ra.GetNumber());
			cout << "\r36%[*********->...............]";
			//4.10 Time Dependence
			TimeDep td(ar.OutReport(), ar.OutVec());
			//td.Detection();
			td.Re_Detection();
			ot.AddString(td.MakeReport(td.GetRowNumber()));
			ot.AddNumber(td.GetNumber());
			cout << "\r40%[**********->..............]";
			//4.11 Malicious libraries
			MaliciousLib ml(ar.OutReport(), ar.OutVec());
			//ml.Detection();
			ml.Re_Detection();
			ot.AddString(ml.MakeReport(ml.GetRowNumber()));
			ot.AddNumber(ml.GetNumber());
			cout << "\r44%[***********->.............]";
			//4.12 Address Type with fixed value
			Address ad(ar.OutReport(), ar.OutVec());
			//ad.Detection();
			ad.Re_Detection();
			ot.AddString(ad.MakeReport(ad.GetRowNumber()));
			ot.AddNumber(ad.GetNumber());
			cout << "\r48%[************->............]";
			//4.13 Integer Division
			IntDivision id(ar.OutReport(), ar.OutVec());
			//id.Detection();
			id.Re_Detection();
			ot.AddString(id.MakeReport(id.GetRowNumber()));
			ot.AddNumber(id.GetNumber());
			cout << "\r52%[*************->...........]";
			//4.14 Locked Money
			LM_Match lm_ma;
			LockedMoney lm(ar.OutReport(), ar.OutVec());
			//lm.Detection();
			lm.Re_Detection(lm_ma);
			ot.AddString(lm.MakeReport(lm.GetRowNumber()));
			ot.AddNumber(lm.GetNumber());
			cout << "\r56%[**************->..........]";
			//4.15 Byte Array
			ByteArray ba(ar.OutReport(), ar.OutVec());
			//ba.Detection();
			ba.Re_Detection();
			ot.AddString(ba.MakeReport(ba.GetRowNumber()));
			ot.AddNumber(ba.GetNumber());
			cout << "\r60%[***************->.........]";
			//4.16 Redundant fallback
			RedFallback rf(ar.OutReport(), ar.OutVec());
			//rf.Detection();
			rf.Re_Detection();
			ot.AddString(rf.MakeReport(rf.GetRowNumber()));
			ot.AddNumber(rf.GetNumber());
			cout << "\r64%[****************->........]";
			//4.17 Irregular style
			IrregularStyle is(ar.OutReport(), ar.OutVec());
			//is.Detection();
			is.Re_Detection();
			ot.AddString(is.MakeReport(is.GetRowNumber()));
			ot.AddNumber(is.GetNumber());
			cout << "\r68%[*****************->.......]";
			//4.18 Visibility Level
			VL_Match vl_match;
			ViLevel vl(ar.OutReport(), ar.OutVec());
			//vl.Re_Detection(vl_match);
			vl.New_Re_Detection(vl_match);
			ot.AddString(vl.MakeReport(vl.GetRowNumber()));
			ot.AddNumber(vl.GetNumber());
			cout << "\r72%[******************->......]";
			//4.19 Using float
			FixedFloat ff(ar.OutReport(), ar.OutVec());
			//ff.Detection();
			ff.Re_Detection();
			ot.AddString(ff.MakeReport(ff.GetRowNumber()));
			ot.AddNumber(ff.GetNumber());
			cout << "\r76%[*******************->.....]";
			//4.20 Transfer forwards all gas
			AllGas ag(ar.OutReport(), ar.OutVec());
			//ag.Detection();
			ag.Re_Detection();
			ot.AddString(ag.MakeReport(ag.GetRowNumber()));
			ot.AddNumber(ag.GetNumber());
			cout << "\r80%[********************->....]";
			//4.21 ERC20 API conflict
			EC_Match ec;
			ERC20 erc(ar.OutReport(), ar.OutVec());
			erc.Detection(ec);
			ot.AddString(erc.MakeReport(erc.GetRowNumber()));
			ot.AddNumber(erc.GetNumber());
			cout << "\r84%[*********************->...]";
			//4.22 Dos by external call
			Dos ds(ar.OutReport(), ar.OutVec());
			//ds.Detection();
			ds.Re_Detection();
			ot.AddString(ds.MakeReport(ds.GetRowNumber()));
			ot.AddNumber(ds.GetNumber());
			cout << "\r88%[**********************->..]";
			//4.23 Miss constructor
			MissConstru mc(ar.OutReport(), ar.OutVec());
			//mc.re_detection()
			mc.Re_Detection();
			ot.AddString(mc.MakeReport(mc.getRowNumber()));
			ot.AddNumber(mc.GetNumber());
			cout << "\r92%[***********************->.]";
			//4.24 Careful use of self-destructive functions
			Selfdestruct sd(ar.OutReport(), ar.OutVec());
			sd.Re_Detection();
			ot.AddString(sd.MakeReport(sd.getRowNumber()));
			ot.AddNumber(sd.GetNumber());
			cout << "\r100%[************************->]";
			cout << endl;
			ot.OutReport(t);
			cout << "file name: " << ar.OutReport() << endl;
			//for keep the window
			cout << "-----End of detection-----\n";
			cout << "Knocking enter twice to exit.\n";
	}
	t.endTime();
	cout << t.timeConsuming_ds() << endl;
	cout << "done.\n";
}

void Overflow_D() {
	//1.get file content
	FileIO io;
	io.ReadIn();
	//2.formatting file content
	ArrangeCode ar(io.OutString(), io.outFileName());
	ar.FormatCode();
	ar.StrToVec(ar.OutOldString());
	io.OutToFile(ar.OutNewName(), ar.VecToStr(ar.OutVec()));
	Output ot(io.outFileName(), ar.OutReport(), io.GetRows());
	//3.backup formatting content
	FileBackup fb(ar.OutOldName(), ar.OutVec());
	fb.OutBackFile();
	// Detection overflow
	Overflow of(ar.OutReport(), ar.OutVec());
	of.Detection();
	//for keep the window
	cout << "Knocking enter twice to exit.\n";
	cin.get();
	cin.get();
	return;
}

void Detection() {
	Time t;
	//1.get file content
	FileIO io;
	t.startTime();
	io.ReadIn();
	//2.formatting file content
	ArrangeCode ar(io.OutString(), io.outFileName());
	ar.FormatCode();
	ar.StrToVec(ar.OutOldString());
	io.OutToFile(ar.OutNewName(), ar.VecToStr(ar.OutVec()));
	Output ot(io.outFileName(), ar.OutReport(), io.GetRows());
	//3.backup formatting content
	FileBackup fb(ar.OutOldName(), ar.OutVec());
	fb.OutBackFile();
	//4.detection of vulnerabilities
	//4.1 Private Modifier
	cout << "-----Start detecting-----\n";
	cout << "0%[->........................]";
	PriModifier pr(ar.OutReport(), ar.OutVec());
	pr.Detection();
	ot.AddString(pr.MakeReport(pr.GetRowNumber()));
	ot.AddNumber(pr.GetNumber());
	cout << "\r4%[*->.......................]";
	//4.2 Costly Loop
	Match ma;
	CostlyLoop cl(ar.OutReport(), ar.OutVec());
	cl.Detection(ma);
	ot.AddString(cl.MakeReport(cl.GetRowNumber()));
	ot.AddNumber(cl.GetNumber());
	cout << "\r8%[**->......................]";
	//4.3 Balance equality
	Balance be(ar.OutReport(), ar.OutVec());
	//be.Detection();
	be.Re_Detection();
	ot.AddString(be.MakeReport(be.GetRowNumber()));
	ot.AddNumber(be.GetNumber());
	cout << "\r12%[***->.....................]";
	//4.4 Unchecked external call
	Call uc(ar.OutReport(), ar.OutVec());
	//uc.Detection();
	uc.Re_Detection();
	ot.AddString(uc.MakeReport(uc.GetRowNumber()));
	ot.AddNumber(uc.GetNumber());
	cout << "\r16%[****->....................]";
	//4.5 Using Tx.origin
	TxOrigin tx(ar.OutReport(), ar.OutVec());
	//tx.Detection();
	tx.Re_Detection();
	ot.AddString(tx.MakeReport(tx.GetRowNumber()));
	ot.AddNumber(tx.GetNumber());
	cout << "\r20%[*****->...................]";
	//4.6 Unsafe type inference
	TypeInfer ti(ar.OutReport(), ar.OutVec());
	//ti.Detection();
	ti.Re_Detection();
	ot.AddString(ti.MakeReport(ti.GetRowNumber()));
	ot.AddNumber(ti.GetNumber());
	cout << "\r24%[******->..................]";
	//4.7 Detect complier version
	VersionNum vn(ar.OutReport(), ar.OutVec());
	//vn.Detection();
	vn.Re_Detection();
	ot.AddString(vn.MakeReport(vn.GetRowNumber()));
	ot.AddNumber(vn.GetNumber());
	cout << "\r28%[*******->.................]";
	/*
	//4.8 Detect send instead of transfer
	Send se(ar.OutReport(), ar.OutVec());
	//se.Detection();
	se.Re_Detection();
	ot.AddString(se.MakeReport(se.GetRowNumber()));
	ot.AddNumber(se.GetNumber());
	*/
	cout << "\r32%[********->................]";
	//4.9 Using random numbers
	//RA_Match rma;
	/*
	Random ra(ar.OutReport(), ar.OutVec());
	//ra.Detection(rma);
	ra.Re_Detection();
	ot.AddString(ra.MakeReport(ra.GetRowNumber()));
	ot.AddNumber(ra.GetNumber());
	*/
	cout << "\r36%[*********->...............]";
	//4.10 Time Dependence
	TimeDep td(ar.OutReport(), ar.OutVec());
	//td.Detection();
	td.Re_Detection();
	ot.AddString(td.MakeReport(td.GetRowNumber()));
	ot.AddNumber(td.GetNumber());
	cout << "\r40%[**********->..............]";
	//4.11 Malicious libraries
	/*
	MaliciousLib ml(ar.OutReport(), ar.OutVec());
	//ml.Detection();
	ml.Re_Detection();
	ot.AddString(ml.MakeReport(ml.GetRowNumber()));
	ot.AddNumber(ml.GetNumber());
	*/
	cout << "\r44%[***********->.............]";
	//4.12 Address Type with fixed value
	/*
	Address ad(ar.OutReport(), ar.OutVec());
	//ad.Detection();
	ad.Re_Detection();
	ot.AddString(ad.MakeReport(ad.GetRowNumber()));
	ot.AddNumber(ad.GetNumber());
	*/
	cout << "\r48%[************->............]";
	//4.13 Integer Division
	IntDivision id(ar.OutReport(), ar.OutVec());
	//id.Detection();
	id.Re_Detection();
	ot.AddString(id.MakeReport(id.GetRowNumber()));
	ot.AddNumber(id.GetNumber());
	cout << "\r52%[*************->...........]";
	//4.14 Locked Money
	LM_Match lm_ma;
	LockedMoney lm(ar.OutReport(), ar.OutVec());
	//lm.Detection();
	lm.Re_Detection(lm_ma);
	ot.AddString(lm.MakeReport(lm.GetRowNumber()));
	ot.AddNumber(lm.GetNumber());
	cout << "\r56%[**************->..........]";
	//4.15 Byte Array
	ByteArray ba(ar.OutReport(), ar.OutVec());
	//ba.Detection();
	ba.Re_Detection();
	ot.AddString(ba.MakeReport(ba.GetRowNumber()));
	ot.AddNumber(ba.GetNumber());
	cout << "\r60%[***************->.........]";
	//4.16 Redundant fallback
	RedFallback rf(ar.OutReport(), ar.OutVec());
	//rf.Detection();
	rf.Re_Detection();
	ot.AddString(rf.MakeReport(rf.GetRowNumber()));
	ot.AddNumber(rf.GetNumber());
	cout << "\r64%[****************->........]";
	//4.17 Irregular style
	IrregularStyle is(ar.OutReport(), ar.OutVec());
	//is.Detection();
	is.Re_Detection();
	ot.AddString(is.MakeReport(is.GetRowNumber()));
	ot.AddNumber(is.GetNumber());
	cout << "\r68%[*****************->.......]";
	//4.18 Visibility Level
	VL_Match vl_match;
	ViLevel vl(ar.OutReport(), ar.OutVec());
	//vl.Re_Detection(vl_match);
	vl.New_Re_Detection(vl_match);
	ot.AddString(vl.MakeReport(vl.GetRowNumber()));
	ot.AddNumber(vl.GetNumber());
	cout << "\r72%[******************->......]";
	//4.19 Using float
	FixedFloat ff(ar.OutReport(), ar.OutVec());
	//ff.Detection();
	ff.Re_Detection();
	ot.AddString(ff.MakeReport(ff.GetRowNumber()));
	ot.AddNumber(ff.GetNumber());
	cout << "\r76%[*******************->.....]";
	//4.20 Transfer forwards all gas
	/*
	AllGas ag(ar.OutReport(), ar.OutVec());
	//ag.Detection();
	ag.Re_Detection();
	ot.AddString(ag.MakeReport(ag.GetRowNumber()));
	ot.AddNumber(ag.GetNumber());
	cout << "\r80%[********************->....]";
	*/
	//4.21 ERC20 API conflict
	EC_Match ec;
	ERC20 erc(ar.OutReport(), ar.OutVec());
	erc.Detection(ec);
	ot.AddString(erc.MakeReport(erc.GetRowNumber()));
	ot.AddNumber(erc.GetNumber());
	cout << "\r84%[*********************->...]";
	//4.22 Dos by external call
	Dos ds(ar.OutReport(), ar.OutVec());
	//ds.Detection();
	ds.Re_Detection();
	ot.AddString(ds.MakeReport(ds.GetRowNumber()));
	ot.AddNumber(ds.GetNumber());
	cout << "\r88%[**********************->..]";
	//4.23 Miss constructor
	MissConstru mc(ar.OutReport(), ar.OutVec());
	//mc.re_detection()
	mc.Re_Detection();
	ot.AddString(mc.MakeReport(mc.getRowNumber()));
	ot.AddNumber(mc.GetNumber());
	cout << "\r92%[***********************->.]";
	/*
	//4.24 Careful use of self-destructive functions
	Selfdestruct sd(ar.OutReport(), ar.OutVec());
	sd.Re_Detection();
	ot.AddString(sd.MakeReport(sd.getRowNumber()));
	ot.AddNumber(sd.GetNumber());
	*/
	cout << "\r100%[************************->]";
	cout << endl;
	//5. end detection and output report
	t.endTime();
	ot.OutReport(t);
	cout << "file name: " << ar.OutReport() << endl;
	//for keep the window
	cout << "-----End of detection-----\n";
	cout << "Knocking enter twice to exit.\n";
	cin.get();
	cin.get();
}

void Reentrant_D() {
	FileIO io;
	io.ReadIn();
	//2.formatting file content
	ArrangeCode ar(io.OutString(), io.outFileName());
	ar.FormatCode();
	ar.StrToVec(ar.OutOldString());
	io.OutToFile(ar.OutNewName(), ar.VecToStr(ar.OutVec()));
	Output ot(io.outFileName(), ar.OutReport(), io.GetRows());
	//Detect Reentrancy
	Reentrant re(ar.OutReport(), ar.OutVec());
	//re.Detection();
	re.Re_Detection();
	//whether to Generate Pile Insertion Files
	if (re.IsReentrant(re.GetRowNumber())) {
		InsertCode ic(ar.OutNewName());
		ic.Execute();
		cout << "-----End of detection-----\n";
		cout << "Knocking enter twice to exit.\n";
		cin.get();
		cin.get();
	}
	else {
		cout << "No reentrant.\n";
		cout << "-----End of detection-----\n";
		cout << "Knocking enter twice to exit.\n";
		cin.get();
		cin.get();
		return;
	}
}

void GetLimit() {
	ifstream inFile("GasLimit.ini");
	if (!inFile.is_open()) {
		cout << "Getting Gas limit failed" << endl;
		inFile.close();
		return;
	}
	string gaslimit;
	inFile >> gaslimit;
	inFile.close();
	cout << "current gas limit: " << gaslimit << endl;
	return;
}

void SetLimit() {
	int limit;
	cout << "enter new gas limit: ";
	cin >> limit;

	ofstream outFile("GasLimit.ini");

	if (!outFile.is_open()) {
		cout << "Writing Gas limit failed" << endl;
		outFile.close();
		return;
	}
	outFile << limit << endl;
	outFile.close();
	cout << "New gas limit is set.\n";
	return;
}

//test function
void test() {
	FileIO io;
	io.ReadIn();
	//2.formatting file content
	ArrangeCode ar(io.OutString(), io.outFileName());
	ar.FormatCode();
	ar.StrToVec(ar.OutOldString());
	io.OutToFile(ar.OutNewName(), ar.VecToStr(ar.OutVec()));
	Output ot(io.outFileName(), ar.OutReport(), io.GetRows());
	//3.backup formatting content
	FileBackup fb(ar.OutOldName(), ar.OutVec());
	fb.OutBackFile();
	//do test
	MissConstru mc(ar.OutReport(), ar.OutVec());
	mc.Re_Detection();
}

/* run this program using the console pauser or add your own getch, system("pause") or input loop */

int main(int argc, char** argv) {
	if (argc == 2) {
		string command = argv[1];
		if (command == "--help" || command=="-h") {
			OutHelp();
		}
		else if (command == "--r" || command=="-r") {
			Reentrant_D();
		}
		else if (command == "--o" || command=="-o") {
			Overflow_D();
		}
		else if (command == "--d" || command=="-d") {
			Detection();
		}
		else if (command == "--s" || command == "-s") {
			SetLimit();
		}
		else if (command == "--g" || command == "-g") {
			GetLimit();
		}
		else if (command == "--f" || command == "-f") {
			Detection_F();
		}
		else if (command == "--t" || command == "-t") {
			test();
		}
		else {
			cout << "wrong parameter.\n";
			cout << "Enter \"SolidityCheck --help\" to get help information.\n";
		}
		return 1;
	}
	else {
		cout << "Incorrect parameter numbers.\n";
		cout << "Enter \"SolidityCheck --help\" to get help information.\n";
		return -1;
	}
	return 0;
}