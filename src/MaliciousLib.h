//
// Created by xiaofeng on 2019/11/29.
//


//This program is used to detect whether the program depends on external
//libraries or not.

//head file

/*
author=__xiaofeng__
*/

#ifndef _MALICIOUSLIB_H_
#define _MALICIOUSLIB_H_

//using head files
#include <vector>
#include <string>
#include <cctype>
#include <algorithm>
#include <iterator>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string ML_LIB = " library ";
const static string ML_IF1 = " if(";
const static string ML_IF2 = " if ";
const static string ML_REQUIRE1 = " require(";
const static string ML_REQUIRE2 = " reuqire ";

//regex detection
const static string ML_RE_LIB = "^(\\s)*(library)(\\s)+(\\w)+(\\s)*(\\{)$";
const static string ML_RE_FUN_SUFFIX = "(\\.)(\\w)+(\\()(.)*(\\))";
const static string ML_RE_IF = "^(\\s)*((if)|(require))(\\s)*(\\()(.)+(\\))(\\s)*((;)|(\\{)|(\\}))$";

//class maliciouslib
class MaliciousLib {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string MLName;
    string OtherOperation;
    //libraries' name
    vector<string> LibNames;
    //error or warning
    bool flag;
protected:
    bool IsLib(const string& _str);
    void GetLibName(const string& _str);
    bool IsLibCall(const string& _str);
    bool IsIf(const string& _str);
    bool IsRequire(const string& _str);
public:
    //constructor
    MaliciousLib(const string _report_name, const vector<string> _content);
    //destructor
    ~MaliciousLib();
    //get detect report
    string MakeReport(const vector<int>& _row_number);
    //execute detection
    void Detection();
    //regex detection
    void Re_Detection();
    //return row_number.size()
    int GetNumber();
    //return row_number
    vector<int> GetRowNumber();
    //print lib names
    void OutLibName();
};

#endif