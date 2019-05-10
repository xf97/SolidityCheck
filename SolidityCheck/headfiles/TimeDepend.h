//Timestamp may be affected to some extent by miners. Depending on time stamp, 
//miners will gain unfair competitive advantage.

//head file

/*
author=__xiaofeng__
*/

#ifndef _TIMEDEPEND_H_
#define _TIMEDEPEND_H_

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
const static string TD_NOW = "now";
const static string TD_BLOCK = "block.timestamp";

//regex
const static string TD_RE_TIME = "(((\\b)(now)(\\b))|((\\b)(block.timestamp)(\\b)))";

//class TimeDep
class TimeDep {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string TDName;
	string OtherOperation;
protected:
	bool IsTime(const string& _str);
	bool GetIdentifier(const string& _str);
public:
	//constructor
	TimeDep(const string _report_name, const vector<string> _content);
	//destructor
	~TimeDep();
	//get detect report
	string MakeReport(const vector<int>& _row_number);
	//execute detection
	void Detection();
	//return row_number size
	int GetNumber();
	//return row_number
	vector<int> GetRowNumber();
	//regex detection
	void Re_Detection();
};

#endif
