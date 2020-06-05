//
// Created by xiaofeng on 2019/11/29.
//

#pragma once
//Solidity does not yet fully support fixed-length floating-point type.
//Fixed-length floating-point variables can be declared, but they cannot
//be assigned or assigned to other variables.

//head files

/*
author=__xiaofeng__
*/

#ifndef _FIXEDFLOAT_H_
#define _FIXEDFLOAT_H_

//using head files
#include <vector>
#include <string>
#include <cctype>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string FF_FIXED1 = " fixed ";
const static string FF_UFIXED1 = " ufixed ";
const static string FF_FIXED2 = "fixed";
const static string FF_UFIXED2 = "ufixed";
const static char FF_CHEN = '*';

//regex
const static string FF_RE_FLOAT = "(\\b)((ufixed)|(fixed))((\\d){1,3}(x)(\\d){0,2})?(\\s)+(\\w)+";

//class FixedFloat
class FixedFloat {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string FFName;
    string OtherOperation;
protected:
    bool OnlyFixed(const string& _str);
    bool ReFixed(const string& _str);
public:
    //constructor
    FixedFloat(const string _report_name, const vector<string> _content);
    //destructor
    ~FixedFloat();
    //get detect report
    string MakeReport(const vector<int>& _row_number);
    //return row_number.size()
    int GetNumber();
    //return row_number
    vector<int> GetRowNumber();
    //execute detection
    void Detection();
    //regex detection
    void Re_Detection();
};

#endif // !_FIXEDFLOAT_H_

