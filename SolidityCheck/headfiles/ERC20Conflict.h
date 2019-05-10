#pragma once
//In ERC20-compliant contracts, we do not recommend throwing exceptions in
//functions that return bool values, such as approve, transfer, transferFrom

//head file

/*
author=__xiaofeng__
*/

#ifndef _ERC20CONFLICT_H_
#define _ERC20CONFLICT_H_

//using head files
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <cctype>
#include <sstream>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string EC_ERC20 = "ERC20";
const static string EC_CON = " contract ";
const static string EC_INT = " interface ";
const static string EC_LIB = " library ";
const static string EC_FUN1 = " function ";
const static string EC_FUN2 = "function";
const static string EC_APPROVE = "approve";
const static string EC_TRANSFER = "transfer";
const static string EC_TRANSFROM = "transferFrom";
const static string EC_REVERT1 = " revert ";
const static string EC_REVERT2 = " revert(";
const static string EC_THROW1 = " throw;";
const static string EC_THROW2 = " throw ";
const static string EC_ASSERT1 = " assert ";
const static string EC_ASSERT2 = " assert(";
const static string EC_REQUIRE1 = " require ";
const static string EC_REQUIRE2 = " require(";
const static string EC_INHERIT = " is ";

//regex 
const static string EC_RE_ERC20 = "(\\s)*((contract)|(interface))(\\s)+(\\w)*((ERC)|(ERc)|(eRC)|(eRc)|(ErC)|(Erc)|(erC)|(erc))(20)(\\w)*((\\s)|(\\{)|(;))";

//class match brackets
class EC_Match {
private:
	vector<char> brackets;
	int count;
public:
	EC_Match() {
		count = 0;
	}
	~EC_Match() {
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

//class ERC20
class ERC20 {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string ECName;
	string OtherOperation;
	bool ERC20Flag;
	vector<string> chain;
protected:
	bool IsCI(const string& _str);
	void GetFunName(const string& _str, string& _name);
	bool IsCon(const string& _str);
	bool IsInt(const string& _str);
	void GetName(const string _str, string& _name);
	bool IsERC20(const string& _str);
	void GetSons(vector<string>& _name);
	bool IsSon(const vector<string>& _name, const string& _temp);
	bool IsCIL(const string& _str);
	bool IsExcep(const string& _str);
	bool IsSonClass(const string& _str);
	void GetFatherName(const string& _str, vector<string>& fname);
	void OutVec(const vector<string>& _vec);
	bool InVec(const vector<string>& _vec, const vector<string>& _name);
	void MergeVec(const vector<string>& source,vector<string>& dest);
	string GetSonName(const string& _str);
	void split(const string& _str, vector<string>& vec, const char flag = ',');
	bool IsChain(const string& _str);
	bool IsFun(const string& _str);
	string GetUpper(const string& temp);
public:
	ERC20(const string _report_name, const vector<string> _content);
	~ERC20();
	string MakeReport(const vector<int>& _row_number);
	int GetNumber();
	vector<int> GetRowNumber();
	void Detection(EC_Match& ec);
	//regex Detection
	void Re_Detection();
};
#endif // !_ERC20CONFLICT_H_
