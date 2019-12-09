//
// Created by xiaofeng on 2019/11/29.
//
#pragma once
//This program is used to judge integer division.

//head file

/*
author=__xiaofeng__
*/

#ifndef  _INTDIVISION_H_
#define _INTDIVISION_H_

//using head file
#include <vector>
#include <string>
#include <cctype>
#include <algorithm>
#include <iterator>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string ID_DIV = "/";

//regex
const static string ID_RE_DIV = "(\\d)+(\\s)*(\\/)(\\s)*(\\d)+";

//class intdivision
class IntDivision {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string IDName;
    string OtherOperation;
protected:
    bool IsDivision(const string& _str);
    void GetIndex(const string& _str,vector<int>& _index);
    void GetLeft(string& _str, int _index,const string& _sta);
    void GetRight(string& _str, int _index,const string& _sta);
    bool IsInt(const string& _str);
public:
    //constructor
    IntDivision(const string _report_name, const vector<string> _content);
    //destructor
    ~IntDivision();
    //get detect report
    string MakeReport(const vector<int>& _row_number);
    //get row_number.size()
    int GetNumber();
    //get row_number
    vector<int> GetRowNumber();
    //execute detection
    void Detection();
    //regex detection
    void Re_Detection();
};

#endif // ! _INTDIVISION_H_
