//
// Created by xiaofeng on 2019/11/29.
//

//This program is used to detect statements
//that may introduce reentry vulnerabilities

//head file

/*
author=__xiaofeng__
*/

//Assuming that the grammar of each contract code used for detection is correct
//reentry detection ".call.value(" keyword
//if the key word is included in the contract, the program records the line number
//that appears,  the possible risks, and provides a smart contract
//that can detect reentry vulnerabilities (by code stuffing)

#ifndef _REENTRANT_H_
#define _REENTRANT_H_

//using head files
#include <vector>
#include <string>
#include <fstream>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string REKEY = ".call.value";

//regex
const static string RE_RE_CALL = "(.)+(\\.)(call)(\\.)(value)(\\s)*(\\()(.)+(\\))(\\()(\\))";
//const static string RE_RE_CALL1 = r"(.)+(\.)(call)(\.)(value)(\s)*(\()(.)+(\))(\()\"\"(\))";
//const static string V5_CALL = ".call.value(";
//const static string V5_CALL1 = ")("")";
const static string RE_RE_CALL1 = "(.)+(\\.)(call)(\\.)(value)(\\s)*(\\()(.)+(\\))(\\()\"\"(\\))";

//reentrant detect class
class Reentrant {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string ReName;
    string OtherOperation;
protected:
    string ProcessBar(const int _rate);
public:
    //constructor
    Reentrant(const string _report_name, const vector<string> _content);
    //destructor
    ~Reentrant();
    //execute detection
    void Detection();
    //regex detection
    void Re_Detection();
    //whether to start piling
    bool IsReentrant(const vector<int>& _row_number);
    //get detect report
    string MakeReport(const vector<int>& _row_number);
    //return row_number size
    int GetNumber();
    //return row_number
    vector<int> GetRowNumber();
};



#endif
