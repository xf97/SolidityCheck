#pragma once
//This part of the program is used to detect statements that may cause integer overflow, 
//and to deal with possible overflow errors by inserting statements.

//head file

/*
author=__xiaofeng__
*/

#ifndef  _OVERFLOW_H_
#define _OVERFLOW_H_

//using head files
#include <string>
#include <vector>
#include <regex>
#include <iterator>
#include <algorithm>
#include <cctype>
#include <fstream>

//using namespace 
using namespace std;

//const constant
const static string OF_RE_OPERATION = "^(\\s)*(\\w)*(\\s)+((\\w)|(\\()|(\\))|(\\[)|(\\])|(\\.))+(\\s)*(=)(\\s)*((\\w)|(\\()|(\\))|(\\[)|(\\])|(\\.))+(\\s)*((\\+)|(\\-)|(\\*)|(\\/)|(\\%))(\\s)*((\\w)|(\\()|(\\))|(\\[)|(\\])|(\\.))+(\\s)*(;)$";
const static string OF_RE_NEW_OPERATION = "^(\\s)*(\\w)*(\\s)+((\\w)|(\\()|(\\))|(\\[)|(\\])|(\\.))+(\\s)*(((\\+)(\\=))|((\\-)(\\=))|(\\*)(\\=)|(\\/)(\\=)|(\\%)(\\=))(\\s)*((\\w)|(\\()|(\\))|(\\[)|(\\])|(\\.))+(\\s)*(;)$";
const static string OF_LIBRARY = " library ";
const static string OF_CONTRACT = " contract ";
const static string OF_INTERFACE = " interface ";
const static string OF_NO_OVERFLOW = "_no_overflow.sol";
const static string OF_POSITION = "overflow_insert_position.txt";
//class overflow
class Overflow {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string OFName;
	string OtherOperation;
	bool InsertFlag;
protected:
	string GetVariable(int _count);
	string RewriteCon(const string _str, const vector<string>& _ope,int _count);
	string GetLeft(const string& _str);
	string GetRight(const string& _str);
	string RewriteSta(const string& _str);
	string ProcessBar(const int _rate);
	bool IsOperation(const string& _str);
	bool IsSafeMath(const string& _str);
	int GetStartIndex(const int i);
	bool IsCIL(const string& _str);
	void OutVec(const vector<string>& _vec);
	vector<string> GetOpe(const string& _str);
	string GetCode(const string& _str, const vector<string>& _ope,bool _flag,string _vari);
	int GetType(const string& _str);
	int GetNewType(const string& _str);
	void OutputPosition();
	bool NewIsOperation(const string& _str);
public:
	Overflow(const string _report_name, const vector<string> _content);
	~Overflow();
	string MakeReport(const vector<int>& _row_number);
	int GetNumber();
	vector<int> GetRowNumber();
	void Detection();
};
#endif // ! _OVERFLOW_H_
