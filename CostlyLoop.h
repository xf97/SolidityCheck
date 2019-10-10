//This program is used to detect costly loop

//head file

/*
author=_xiaofeng_
*/

//Costly loop by detecting the for or while condition in the presence of any one of the following:
//1.the difference between the initial value and the conditional value exceeds 10000,which can be  adjusted.
//2.variable identifier 
//3.function call 

#ifndef _COSTLYLOOP_H_
#define _COSTLYLOOP_H_

//using head files
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <cctype>
#include <regex>
#include <fstream>

//using namespace 
using namespace std;

//const constants
const static string CL_FOR1 = " for ";
const static string CL_FOR2 = " for(";
const static string CL_WHILE1 = " while ";
const static string CL_WHILE2 = " while(";
const static string CL_CALL1 = "(";
const static string CL_CALL2 = ")";
const static char CL_CALL3 = '.';
const static int PERGAS = 2928;
const static string CL_USING = " using ";

//regex
const static string CL_RE_FOR = "^(\\s)*(for)(\\s)*(\\()(.)+(\\))";
const static string CL_RE_FOR_ATT = "(\\b)(for)(\\s)*(\\()(.)*(;)(.)*(\\.)(.)*(;)(.)*(\\))";
const static string CL_RE_WHILE_ATT = "(\\b)(while)(\\s)*(\\()(.)*(\\.)(.)*(\\))";
const static string CL_RE_FOR_IDEN = "(\\b)(for)(\\s)*(\\()(.)*(;)(.)*(\\w)+(.)*(;)(.)*(\\))";
const static string CL_RE_WHILE_IDEN = "(\\b)(while)(\\s)*(\\()(.)*(\\w)+(.)*(\\))";
const static string CL_RE_FOR_FUN = "(\\b)(for)(\\s)*(\\()(.)*(;)(.)*(\\()(.)*(\\))(.)*(;)(.)*(\\))";
const static string CL_RE_WHILE_FUN = "(\\b)(while)(\\s)*(\\()(.)*(\\()(.)*(\\))(.)*(\\))";


//new regex
const static string CL_RE_NEWFOR = "^(\\s)*(\\b)(for)(\\b)(\\s)*(\\()(.)*(;)(.)*(;)(.)*(\\))(\\s)*(((.)*(;))|(\\{))$";
const static string CL_RE_NEWWHILE = "^(\\s)*(\\b)(while)(\\b)(\\s)*(\\()(.)*(\\))(\\s)*(((.)*(;))|(\\{))$";
const static string CL_RE_NEWCALL = "(\\()(.)*(\\))";


//bracket matching recognition class
class Match {
private:
	//data
	vector<char> brackets;
	int count;
protected:
	bool OnlyRightBracket(const string& _str);
public:
	//constructor
	Match();
	//destructor
	~Match();
	//set new count;
	void Reset();
	//judging whether or not to match 
	bool IsMatching();
	//execute matching
	int DoMatch(const vector<string>& _content, const int _row_number);
};

//costly loop class
class CostlyLoop {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string CLName;
	string OtherOperation;
	int gas_limit;
protected:
	bool IsFor(const string& _str);
	bool IsWhile(const string& _str);
	bool IsCall(const string& _str);
	void split(const string& _str, vector<string>& vec, const char flag = ';');
	bool IsMember(const string& _str);
	string SplitRight(const string& _str);
	bool IsNum(const string& _str);
	string SplitLeft(const string& _str);
	string GetCondition(const string& _str);
	bool Comparative(const int _right, const int _row);
	int StrToInt(const string& _str);
	void OutGasLimit(const int _gas_limit);
public:
	//constructor
	CostlyLoop(const string _report_name, const vector<string> _content);
	//destructor
	~CostlyLoop();
	//execute detection
	void Detection(Match& ma);
	//set new gas_limit
	void SetGasLimit(const int _gas_limit);
	//get present gas_limit
	int GetGasLimit();
	//splicing report string
	string MakeReport(const vector<int>& _row_number);
	//return row_number size
	int GetNumber();
	//return row_number
	vector<int> GetRowNumber();
	//regex detection
	void Re_Detection();
};

#endif
