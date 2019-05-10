
//This program is used to detect unchecked external call vulnerabilities 
//detect method:the detection method is whether the  send()/call/delegatecall()
//statements are in the if/require statemens.

//head file

/*
author=_xiaofeng_
*/

#ifndef _UNCHECKEDCALL_H_
#define _UNCHECKEDCALL_H_

//using head files
#include <vector>
#include <string>
#include <regex>

//using namespace 
using namespace std;

//const constants
const static string UC_IF1 = " if ";
const static string UC_IF2 = "if(";
const static string UC_REQUIRE1 = " require ";
const static string UC_REQUIRE2 = " require(";
const static string UC_SEND1 = ".send(";
const static string UC_SEND2 = ".send ";
const static string UC_CALL1 = ".call(";
const static string UC_CALL2 = ".call ";
const static string UC_CALL3 = ".call.";
const static string UC_DELE1 = ".delegatecall(";
const static string UC_DELE2 = ".delegatecall ";
const static string UC_DELE3 = ".delegatecall.";

//regex definition,regex_search
const static string UC_RE_IF = "^(\\s)*((if)|(require))(\\s)*(\\()(.)*((\\w)|(\\()|(\\))|(\\[)|(\\])|(\\.))+(\\.)((send)|(delegatecall)|(call))(.)*(\\()(.)*(\\))(.)*(\\))";

//Unchecked Call class
class Call {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string UCName;
	string OtherOperation;
protected:
	bool IsExternal(const string& _str);
	bool IsInIf(const string& _str);
	bool IsInRequire(const string& _str);
	bool IsCall(const string& _str);
	bool IsDele(const string& _str);
	bool IsSend(const string& _str);
public:
	//constructor
	Call(const string _report_name, const vector<string> _content);
	//destructor
	~Call();
	//make detection report
	string MakeReport(const vector<int>& _row_number);
	//execute detection
	void Detection();
	//regex detection
	void Re_Detection();
	//return row_number size
	int GetNumber();
	//return row_number
	vector<int> GetRowNumber();
};

#endif