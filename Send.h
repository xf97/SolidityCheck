//
// Created by xiaofeng on 2019/11/29.
//

//send instead of transfer.It is recommended to use transfer instead of send to
//send Ethernet currency, so that when an exception occurs to send, the program can
//be terminated.

//head file

/*
author=__xiaofeng__
*/


#ifndef _SEND_H_
#define _SEND_H_

//using head files
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string SE_SEND1 = ".send(";
const static string SE_SEND2 = ".send ";

//regex
const static string SE_RE_SEND = "(.)+(\\.)(send)(\\()(.)+(\\))";

//detect send class
class Send {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string SEName;
    string OtherOperation;
protected:
    bool IsSend(const string& _str);
public:
    //constructor
    Send(const string _report_name, const vector<string> _content);
    //destructor
    ~Send();
    //get detect report
    string MakeReport(const vector<int>& _row_number);
    //execute detection
    void Detection();
    //regex detection
    void Re_Detection();
    //return row_number size
    int GetNumber();
    //return row_number
    vector<int> GetRowNumber();
};


#endif
