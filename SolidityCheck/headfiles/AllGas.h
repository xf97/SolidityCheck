#pragma once
//Using addr. call. value(x)() to transmit Ethernet coins will send all gas,
//which may introduce security risks.

//head file

/*
author=__xiaofeng__
*/

#ifndef  _ALLGAS_H_
#define _ALLGAS_H_

//using head files
#include <vector>
#include <string>
#include <cctype>
#include <regex>

//using namespace 
using namespace std;

//const constants
const static string AG_VALUE = ".value(";
const static string AG_BRACKETS = "()";
const static string AG_GAS = ".gas(";

//regex 
const static string AG_RE_ALLGAS = "(.)+(\\.)(call)(\\.)(value)(\\s)*(\\()(.)+(\\))(\\()(\\s)*(\\))";
const static string AG_RE_NOGAS = "(\\.)(gas)(\\s)*(\\()(.)+(\\))";

//class allgas
class AllGas {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string AGName;
	string OtherOperation;
protected:
	bool IsCallValue(const string& _str);
	bool IsGas(const string& _str);
	void NoBlank(const string& _str, string& _temp);
public:
	AllGas(const string _report_name,const vector<string> _content);
	~AllGas();
	string MakeReport(const vector<int>& _row_number);
	int GetNumber();
	vector<int> GetRowNumber();
	void Detection();
	//regex detection
	void Re_Detection();
};
#endif // ! _ALLGAS_H_
