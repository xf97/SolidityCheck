//This part of the program is used to detect the use
//of random numbers in smart contracts(excluding the 
//use of off-chain services)

//head file

/*
author=_xiaofeng_
*/

#ifndef _RANDOM_H_
#define _RANDOM_H_


//using head files
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <cctype>
#include <regex>

//using namespace 
using namespace std;

//const constants
const static string RA_KECCAK = "keccak256";
const static string RA_SHA256 = "sha256";
const static string RA_SHA3 = "sha3";
const static string RA_RIPEMD = "ripemd160";
const static string RA_BLOCK = "block.timestamp";
const static string RA_NOW = "now";

//regex
const static string RA_RE_RANDOM = "((sha3)|(sha256)|(keccak256)|(ripemd160))(\\s)*(\\()(.)*((block.timestamp)|((\\b)(now)(\\b)))(.)*(\\))";


//class parenthesis matching 
class RA_Match {
private:
	//data
	vector<char> brackets;
	int count;
public:
	//constructor
	RA_Match();
	//destructor
	~RA_Match();
	//set new count;
	void Reset();
	//judging whether or not to match 
	bool IsMatching();
	//execute matching
	vector<string> DoMatch(const string& _str, const vector<int>& _index);
};

//class Random
class Random {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string RAName;
	string OtherOperation;
protected:
	bool IsHash(const string& _str, vector<int>& _index);
	bool IsRandom(const vector<string>& _argu);
public:
	//constructror
	Random(const string _report_name, const vector<string> _content);
	//destructor
	~Random();
	//get detect report
	string MakeReport(const vector<int>& _row_number);
	//execute detection
	void Detection(RA_Match& rma);
	//regex detection
	void Re_Detection();
	//return row_number size
	int GetNumber();
	//return row_number
	vector<int> GetRowNumber();
};



#endif
