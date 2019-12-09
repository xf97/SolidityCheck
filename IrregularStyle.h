//
// Created by xiaofeng on 2019/11/29.
//

#pragma once
//Solidity specifies how functions, events are named, and arrays
//are declared. Compliance with specifications improves code readability

//head file

/*
author=__xiaofeng__
*/

#ifndef _IRREGULARSTYLE_H_
#define _IRREGULARSTYLE_H_

//using head files
#include <vector>
#include <string>
#include <cctype>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string IS_FUNCTION1 = "function";	//attention fallback
const static string IS_FUNCTION2 = " function ";
const static string IS_EVENT1 = "event";
const static string IS_EVENT2 = " event ";
const static char IS_LEFT = '[';
const static char IS_RIGHT = ']';

//regex
const static string IS_RE_FUNCTION = "(\\b)(function)(\\s)+[^a-z](\\w)+";
const static string IS_RE_EVENT = "(\\s)*(event)(\\s)+[^A-Z](\\w)+";
const static string IS_RE_ARRAY = "(\\b)(\\w)+(\\s)+(\\[)(.)*(\\])";

//class irregular style
class IrregularStyle {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string ISName;
    string OtherOperation;
protected:
    bool IsFun(const string& _str);
    bool IsEvent(const string& _str);
    bool IsArray(const string& _str);
    void GetFunName(const string& _str,string& _name);
    void GetEventName(const string& _str, string& _name);
    bool Good(const string& _str);
public:
    //constructor
    IrregularStyle(const string _report_name, const vector<string> _content);
    //destructor
    ~IrregularStyle();
    //get detect report
    string MakeReport(const vector<int>& _row_number);
    //return row_number.size()
    int GetNumber();
    //return row_number;
    vector<int> GetRowNumber();
    //execute detection
    void Detection();
    //regex detection
    void Re_Detection();
};

#endif // !_IRREGULARSTYLE_H_
