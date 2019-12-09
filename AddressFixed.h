//
// Created by xiaofeng on 2019/11/22.
//

#pragma once
//Address type with fixed value
//It is dangerous to assign value to address variables using constants.
//Please check carefully whether the account that the address points to
//is a contract/library.Note that the contract/library may self-destruct.

//head file

/*
author=__xiaofeng__
*/

#ifndef _ADDRESSFIXED_H_
#define _ADDRESSFIXED_H_

//using head files
#include <vector>
#include <string>
#include <cctype>
#include <iterator>
#include <algorithm>
#include <sstream>
#include <regex>

//using namespace
using namespace std;

//const constant
const static string AF_ADDRESS = " address ";
const static string AF_ADDRESS1 = "address ";
const static string AF_0X = "0x";
const static string AF_EQ = "=";

//regex
const static string AF_RE_ADDRESS = "(.)+(\\s)*(=)(\\s)*((0x)|(0X))[0-9A-Fa-f]{40}";

//class address
class Address {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string AFName;
    string OtherOperation;
protected:
    bool IsConst(const string& _str);
    void GetAddressName(string& _name, const string& _str);
    bool IsName(const string& _name,const string& _str);
    bool IsAddress(const string& _str);
    bool IsEqual(const string& _str);
    void GetIdent( string _str,string& _name);
    void split(const string& _str, vector<string>& vec, const char flag = ' ');
    bool RE_IsConst(const string& _str);
public:
    Address(const string _report_name, const vector<string> _content);
    ~Address();
    string MakeReport(const vector<int>& _row_number);
    int GetNumber();
    vector<int> GetRowNumber();
    void Detection();
    //regex detection
    void Re_Detection();
};

#endif // ! _ADDRESSFIXED_H_




