#pragma once
// Explicitly define function visibility to prevent
//confusion

//head file

/*
author=__xiaofeng__
*/


#ifndef _VISIBILITYLEVEL_H_
#define _VISIBILITYLEVEL_H_

//using head files
#include <vector>
#include <string>
#include <cctype>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <regex>

//using namespace 
using namespace std;

//const constants
const static string VL_FUN = " function ";
const static string VL_PUBLIC = " public ";
const static string VL_PRIVATE = " private ";
const static string VL_INTERNAL = " internal ";
const static string VL_EXTERNAL = " external ";
const static string VL_PUBLIC1 = " public;";
const static string VL_PRIVATE1 = " private;";
const static string VL_INTERNAL1 = " internal;";
const static string VL_EXTERNAL1 = " external;";
const static string VL_PUBLIC2 = " public{";
const static string VL_PRIVATE2 = " private{";
const static string VL_INTERNAL2 = " internal{";
const static string VL_EXTERNAL2 = " external{";

const static string VL_FOR1 = " for ";
const static string VL_FOR2 = " for(";
const static string VL_MAP1 = " mapping ";
const static string VL_MAP2 = " mapping(";
const static string VL_BOOL = " bool ";
const static string VL_UINT = "uint";
const static string VL_INT = "int";
const static string VL_FIXED = "fixed";
const static string VL_UFIXED = "ufixed";
const static string VL_ADDRESS = " address ";
const static char VL_LEFT = '[';
const static char VL_RIGHT = ']';
const static string VL_BYTES1 = " bytes ";
const static string VL_STRING = " string ";
const static string VL_BYTE = " byte ";
const static string VL_BYTES2 = "bytes";
const static string VL_MODIFIER = " modifier ";

//regex
//Regular expressions for uint/int variable declarations 
const static string VL_RE_UINT_INT = "^(\\s)*(uint|int)(\\d){0,3}(\\s)+((?!private )(?!public )(?!internal )(?!external ))(\\s)*(\\w)+(\\s)*(=(\\s)*(.)+)?(\\s)*;$";
const static string VL_RE_UINT_INT1 = "^(\\s)*(uint|int)(\\d){0,3}(\\s)(.)+";
const static string VL_RE_UFIXED_FIXED = "^(\\s)*(ufixed|fixed)([0-9]{1,3}\\*[0-9]{1,2})?(\\s)+((?!private )(?!public )(?!internal )(?!external ))(\\s)*(\\w)+(\\s)*(=(\\s)*(.)+)?(\\s)*;$";
const static string VL_RE_UFIXED_FIXED1 = "^(\\s)*(ufixed|fixed)([0-9]{1,3}\\*[0-9]{1,2})?(\\s)(.)+";
const static string VL_RE_ADDRESS = "^(\\s)*(address)(\\s)+((?!private )(?!public )(?!internal )(?!external ))(\\s)*(\\w)+(\\s)*(=(\\s)*(.)+)?(\\s)*;$";
const static string VL_RE_ADDRESS1 = "^(\\s)*(address)(\\s)(.)+";
const static string VL_RE_BOOL = "^(\\s)*(bool)(\\s)+((?!private )(?!public )(?!internal )(?!external ))(\\s)*(\\w)+(\\s)*(=(\\s)*(.)+)?(\\s)*;$";
const static string VL_RE_BOOL1 = "^(\\s)*(bool)(\\s)(.)+";
const static string VL_RE_ARRAY = "^(\\s)*(\\w)+(\\s)*(\\[)(\\s)*(\\w)*(\\s)*(\\])((\\[)(\\s)*(\\w)*(\\s)*(\\]))*(\\s)+((storage )|(memory ))?(\\s)*((?!private )(?!public )(?!internal )(?!external ))(\\s)*(\\w)+(\\s)*(=(\\s)*(new)(.)+)?(\\s)*;$";
const static string VL_RE_BYTE = "^(\\s)*((bytes(\\d){0,2})|(byte))(\\s)+((memory )|(storage ))?(\\s)*((?!private )(?!public )(?!internal )(?!external ))(\\s)*(\\w)+(\\s)*(=(\\s)*(.)+)?(\\s)*;$";
const static string VL_RE_BYTE1 = "^(\\s)*((bytes(\\d){0,2})|(byte))(\\s)(.)+";
const static string VL_RE_MAPPING = "^(\\s)*(mapping)(\\s)*(\\()(\\s)*(\\w)+(\\s)*(=>)(\\s)*(\\w)+(\\))(\\s)+((?!private )(?!public )(?!internal )(?!external ))(\\s)*(\\w)+(\\s)*;$";

//regex new 
const static string VL_RE_NEW_INT = "^(\\s)*((uint)|(int))(\\d){0,3}(\\s)+(\\w)+";
const static string VL_RE_NEW_FIXED = "^(\\s)*((ufixed)|(fixed))((\\d){0,3}(x)(\\d){0,2})?(\\s)+(\\w)+";
const static string VL_RE_NEW_BOOL = "^(\\s)*(bool)(\\s)+(\\w)+";
const static string VL_RE_NEW_ADDRESS = "^(\\s)*(address)(\\s)+(\\w)+";
const static string VL_RE_NEW_MAPPING = "^(\\s)*(mapping)(\\s)*(\\()(\\s)*(\\w)+(\\s)*(\\=)(\\>)(.)+(\\))(\\s)+";
const static string VL_RE_NEW_BYTE = "^(\\s)*((bytes){0,2}|(byte))(\\s)+";
const static string VL_RE_NEW_STRING = "^(\\s)*(string)(\\s)+";
const static string VL_RE_NEW_ARRAY = "^(\\s)*(\\w)+(\\s)*(\\[)(.)*(\\])(\\s)+";
const static string VL_NO_MATCH = "(( private )|( public )|( internal )|( external ))";

//class VL_Match for match brackets
class VL_Match {
private:
	vector<char> brackets;
	int count;
public:
	VL_Match() {
		count = 0;
	}
	~VL_Match() {
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



//class ViLevel
class ViLevel {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string VLName;
	string OtherOperation;
protected:
	bool IsFun(const string& _str);
	bool IsVisibility(const string& _str);
	bool IsIllegalState(const string& _str);
	bool IsMapping(const string& _str);
	bool IsBool(const string& _str);
	bool IsUint(const string& _str);
	bool IsFixed(const string& _str);
	bool IsAddress(const string& _str);
	bool IsArray(const string& _str);
	bool IsBytes(const string& _str);
	bool IsVisibility1(const string& _str);
	bool IsVisibility2(const string& _str);
	bool IsModifier(const string& _str);
	bool New_IsIllegalState(const string& _str);
public:
	//constructor
	ViLevel(const string _report_name, const vector<string> _content);
	//destructor
	~ViLevel();
	//get detect report
	string MakeReport(const vector<int>& _row_number);
	//return row_number.size()
	int GetNumber();
	//return row_numner
	vector<int> GetRowNumber();
	//execute detection
	void Detection();
	//use regex to detect
	void Re_Detection(VL_Match& vl);
	//new regex 
	void New_Re_Detection(VL_Match& vl);
};

#endif // !_VISIBILITYLEVEL_H_
