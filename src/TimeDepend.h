//
// Created by xiaofeng on 2019/11/29.
//

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
const static string TD_RE_BLOCKNUMBER = "(\\b)(block)(\\.)(number)(\\b)";
const static string TD_RE_COINBASE = "(\\b)(block)(\\.)(coinbase)(\\b)";
const static string TD_RE_DIFFICULTY = "(\\b)(block)(\\.)(difficulty)(\\b)";
const static string TD_RE_BLOCKHASH1 = "(\\b)(blockhash)(\\s)*(\\()";
const static string TD_RE_BLOCKHASH2 = "(\\b)(block)(\\.)(blockhash)(\\s)*(\\()";

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
