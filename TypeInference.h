//
// Created by xiaofeng on 2019/11/29.
//

//Unsafe type inference. Using type inference can lead to erroneous
//consequences (such as infinite loops).

//head file

/*
author=__xiaofeng__
*/

#ifndef _TYPEINFERENCE_H_
#define _TYPEINFERENCE_H_

//using head files
#include <vector>
#include <string>
#include <cctype>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <cmath>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string TI_VAR1 = " var ";
const static string TI_VAR2 = "(var ";
const static string TI_FOR1 = " for ";
const static string TI_FOR2 = " for(";
const static string TI_USING = " using ";
const static double TI_MAX = pow(2, 198);
const static double TI_MIN = (-1)*pow(2, 197);

//regex
const static string TI_RE_VAR = "(\\b)(var)(\\b)(\\s)+(\\w)+(\\s)*(=)(\\s)*(\\d)+(\\b)";

//type inference class
class TypeInfer {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string TIName;
    string OtherOperation;
protected:
    bool IsVar(const string& _str);
    string SplitRight(const string& _str);
    bool IsNum(const string& _str);
    bool Leak(const string& _str);
    bool IsFor(const string& _str);
    void split(const string& _str, vector<string>& vec, const char flag = ';');
    double Transform(const string& _right);
public:
    //constructor
    TypeInfer(const string _report_name, const vector<string> _content);
    //destrutor
    ~TypeInfer();
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
