//
// Created by xiaofeng on 2019/11/29.
//

//The program detects the use of tx.origin for authentication

/*
author=_xiaofeng_
*/

//head file

#ifndef _TXORIGIN_H_
#define _TXORIGIN_H_

//using head files
#include <vector>
#include <string>
#include <regex>

//using namespace
using namespace std;

//const constants
const static string TO_REQUIRE1 = " require(";
const static string TO_REQUIRE2 = " require ";
const static string TO_IF1 = " if(";
const static string TO_IF2 = " if ";
const static string TO_TX = "tx.origin";

//regex
const static string TO_RE_TX = "^(\\s)*((require)|(if))(\\s)*(\\()(.)*(tx.origin)(.)*(\\))(\\s)*";


//tx.origin class
class TxOrigin {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string TOName;
    string OtherOperation;
protected:
    bool IsTo(const string& _str);
    bool IsIf(const string& _str);
    bool IsRequire(const string& _str);
public:
    //constructor
    TxOrigin(const string _report_name, const vector<string> _content);
    //destructor
    ~TxOrigin();
    //make detect report
    string MakeReport(const vector<int>& _row_name);
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

