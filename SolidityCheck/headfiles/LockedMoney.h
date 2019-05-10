#pragma once
//This part of the procedure is used to detect contracts that can accept 
//external transfers but cannot be transferred.

//head file

/*
author=__xiaofeng__
*/

#ifndef _LOCKEDMONEY_H_
#define _LOCKEDMONEY_H_

//using head files
#include <vector>
#include <string>
#include <regex>

//using namespace 
using namespace std;

//const constants
const static string LM_PAY = " payable ";
const static string LM_CALLVALUE = "call.value";
const static string LM_TRANSFER = ".transfer(";
const static string LM_SEND = ".send(";

//regex
const static string LM_RE_MONEY = "(\\s)*(function)(\\s)(.)+(\\))(.)*(\\s)(payable)((\\s)|(\\{)|(;))";
const static string LM_RE_TRAN_SEND = "(\\.)((transfer)|(send))(\\s)*(\\()(.)+(\\))";
const static string LM_RE_CALL = "(\\.)(call)(\\.)(\\s)*((value)|((gas)(\\()(.)+(\\))(\\.)(value)))(\\()";
const static string LM_ASSEMBLY = "(\\b)(assembly)(\\b)";

//class VL_Match for match brackets
class LM_Match {
private:
	vector<char> brackets;
	int count;
public:
	LM_Match() {
		count = 0;
	}
	~LM_Match() {
		brackets.clear();
		count = 0;
	}
	void Reset() {
		brackets.clear();
		count = 0;
	}
	void Match(const string& _str);
	bool IsMatch() {
		if (brackets.empty() && count != 0)
			return true;
		return false;
	}
};

//class locked money
class LockedMoney {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string LMName;
	string OtherOperation;
	bool flag;
protected:
	bool IsAssembly_Transfer(const string& _str);
	bool IsAssembly(const string& _str);
	bool IsPayable(const string& _str);
	bool IsSend(const string& _str);
	bool IsTransfer(const string& _str);
	bool IsCallValue(const string& _str);
public:
	//constructor
	LockedMoney(const string _report_name, const vector<string> _content);
	//destructor
	~LockedMoney();
	//make detect report
	string MakeReport(const vector<int>& _row_number);
	//return row_number.size()
	int GetNumber();
	//return row_number
	vector<int> GetRowNumber();
	//execute detection
	void Detection();
	//regex detection
	void Re_Detection(LM_Match& lm_ma);
};

#endif // !_LOCKEDMONEY_H_
