//
// Created by xiaofeng on 2019/11/29.
//
#pragma once
//This part of the program is used to detect self-destructive function statements
//There is no method to detect dangerous self-destructive functions based on source
//code in the existing literature. The method we think of is still very elementary:
//to detect the use of each self-destructive function, warning developers.

//head file

/*
author = __xiaofeng__
*/

#ifndef _SELFDESTRUCT_H_
#define _SELFDESTRUCT_H_

//using head files
#include <string>
#include <vector>
#include <iterator>
#include <algorithm>
#include <regex>

//using namespace
using namespace std;

//using constant
//regex
const static string SD_RE_SUICIDE = "^(\\s)*(suicide)(\\s)*(\\()";
const static string SD_RE_SELFDESTRUCT = "^(\\s)*(selfdestruct)(\\s)*(\\()";

//class for detecting self-destructive function
class Selfdestruct {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string SDName;
    string OtherOperation;
public:
    //constructor
    Selfdestruct(const string& _report_name, const vector<string>& _content);
    //destructor
    ~Selfdestruct();
    //making content of report
    string MakeReport(const vector<int>& _row_number);
    //execute detection
    void Re_Detection();
    //return row_number
    vector<int> getRowNumber();
    //return row_number.size
    int GetNumber();
};



#endif // !_SELFDESTRUCT_H_
