#pragma once
//This part of the program is used to detect missing constructor errors, 
//which include not adding constructors, or constructor name spelling errors.

//head file

/*
author = __xiaofeng__
*/

#ifndef _MISSCONSTRUCTOR_
#define _MISSCONSTRUCTOR

//using head files
#include <string>
#include <regex>
#include <iterator>
#include <algorithm>
#include <fstream>
#include <cctype>

//using namespace
using namespace std;

//using constant
//regex
const static string MC_RE_HeadOfContract = "^(\\s)*(contract)(\\s)+(\\w)+(\\s)+(.)*(\\{)$";	//Regular expression matching contract head
const static string MC_RE_Constructor = "^(\\s)*(constructor)(\\s)*(\\()";
//class for bracket matching
class MC_Match {
private:
	//data
	vector<char> brackets;
	int count;
public:
	//constructor
	MC_Match();
	//destructor
	~MC_Match();
	//execute matching
	bool DoMatch(const string& _statement);
};

//Miss Constructor class
class MissConstru {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string MCName;
	string OtherOperation;
protected:
	string getConName(const string& _str);
public:
	MissConstru(const string _report_name, const vector<string> _content);
	~MissConstru();
	//splicing report string
	string MakeReport(const vector<int>& _row_number);
	//execute detection
	void Re_Detection();
	//return row_number
	vector<int> getRowNumber();
	//return row_number.size
	int GetNumber();
};

#endif // !_MISSCONSTRUCTOR_
