#pragma once
//The 0.4.0 version of solidity language will automatically supplement 
//fallback function for contracts. The fallback functions provided by 
//contract writers may bring security risks.

//head file

/*
author=__xiaofeng__
*/

#ifndef _REDFALLBACK_H_
#define _REDFALLBACK_H_

//using head files
#include <vector>
#include <string>
#include <iterator>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string RF_PRAGMA = "pragmasolidity";
const static string RF_FALLBACK = "function()";
const static int RF_LIMIT = 4;

//regex
const static string RF_RE_VERSION = "^(\\s)*(pragma)(\\s)+(solidity)(\\s)+";
const static string RF_RE_FALLBACK = "(\\b)(function)(\\b)(\\s)*(\\()(\\s)*(\\))";

//class redfallback
class RedFallback {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string RFName;
	string OtherOperation;
	int VersionNum;
protected:
	bool IsVersion(const string& _str);
	int GetVersion(const string& _str);
	void split(const string& _str, vector<string>& vec, const char flag = '.');
	bool IsFallback(const string& _str);
public:
	//constructor
	RedFallback(const string _report_name, const vector<string> _content);
	//destructor
	~RedFallback();
	//get detect report
	string MakeReport(const vector<int>& _row_number);
	//return row_number.size()
	int GetNumber();
	//return row_number;
	vector<int> GetRowNumber();
	//execute detection
	void Detection();
	//set default version number
	void SetVerion(const int _v);
	//get default version number
	int GetVersion();
	//regex detection
	void Re_Detection();
};

#endif // !_REDFALLBACK_H_
