//
// Created by xiaofeng on 2019/11/25.
//

#pragma once
//Do not depend on the return value of the external contract, the external
//contract may be killed. Patterns detect if/require/while/for conditional
//judgments that contain external function calls.

//head files

/*
author=__xiaofeng__
*/

#ifndef  _DOSEXTERNAL_H_
#define _DOSEXTERNAL_H_

//using head files
#include <vector>
#include <string>
#include <regex>
#include <cctype>
#include <algorithm>
#include <iterator>

//using namespace
using namespace std;

//const constants
const static string DE_IF1 = " if ";
const static string DE_IF2 = " if(";
const static string DE_FOR1 = " for ";
const static string DE_FOR2 = " for(";
const static string DE_WHILE1 = " while ";
const static string DE_WHILE2 = " while(";
const static string DE_REQUIRE1 = " require ";
const static string DE_REQUIRE2 = " require(";

//const constant
const static string DE_RE_REQUIRE_IF_CALL = "((if)|(while)|(require))(\\s)*(\\()(.)*(\\.)(\\w)+(\\()(.)*(\\))(.)*(\\))";
const static string DE_RE_FOR_CALL = "(for)(\\s)*(\\()(.)*(;)(.)+(\\.)(\\w)+(\\()(.)*(\\))(.)*(;)(.)*(\\))";

//class dos
class Dos {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string DEName;
    string OtherOperation;
protected:
    bool IsRequire(const string& _str);
    bool IsIf(const string& _str);
    bool IsFor(const string& _str);
    bool IsCall(const string& _str);
    bool IsWhile(const string& _str);
public:
    Dos(const string _report_name, const vector<string> _content);
    ~Dos();
    int GetNumber();
    vector<int> GetRowNumber();
    string MakeReport(const vector<int>& _row_number);
    void Detection();
    //regex detection
    void Re_Detection();
};

#endif // ! _DOSEXTERNAL_H_
