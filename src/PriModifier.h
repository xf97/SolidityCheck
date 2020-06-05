//
// Created by xiaofeng on 2019/11/29.
//

//This program is used to detect warnings caused by private modifiers

//head files

/*
author=_xiaofeng_
*/

//Detection: By detecting state variables modified by private modifiers

#ifndef _PRIMODIFIER_H_
#define _PRIMODIFIER_H_

//using head files
#include <vector>
#include <string>
#include <iterator>
#include <algorithm>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string PRI = " private ";
const static string PR_FUN = " function ";
const static string PR_MOD = " modifier ";

//regex
const static string PR_RE_PRIVATE = "(\\b)(private)(\\b)";

//class that detect private state modifiers
class PriModifier {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string PrName;
    string OtherOperation;
public:
    //constructor
    PriModifier(const string _report_name, const vector<string> _content);
    //destructor
    ~PriModifier();
    //execute detection
    void Detection();
    //get detect report
    string MakeReport(const vector<int>& _row_number);
    //return row_number size
    int GetNumber();
    //return row_number
    vector<int> GetRowNumber();
    //regex detection
    void Re_Detection();
};


#endif
