#pragma once
//This part of the program is used to detect the use of byte[]

//head file

/*
author=__xiaofeng__
*/

#ifndef _BYTEARRAY_H_
#define _BYTEARRAY_H_

//using head files
#include <vector>
#include <string>
#include <cctype>
#include <regex>

//using namespace 
using namespace std;

//const constants
const static string BA_BYTE = "byte[]";

//regex
const static string BA_RE_BYTE = "(\\s)*(byte)(\\s)*(\\[)(\\s)*(\\])(\\s)";


//class bytearray
class ByteArray
{
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string BAName;
	string OtherOperation;
protected:
	bool IsByte(const string& _str);
public:
	//constructor
	ByteArray(const string _report_name, const vector<string>& _content);
	//destructor
	~ByteArray();
	//get detect report
	string MakeReport(const vector<int>& _row_number);
	//return row_number.size()
	int GetNumber();
	//return row_number
	vector<int> GetRowNumber();
	//execute detectiom
	void Detection();
	//regex detection
	void Re_Detection();
};


#endif // !_BYTESARRAY_H_
