//
// Created by xiaofeng on 2019/11/29.
//

//This part of the program is used to detect version number problems.
//Using operators or unspecified security specifications can lead to
//unexpected consequences.

//head file

/*
author=__xiaofeng__
*/

#ifndef _VERSIONNUM_H_
#define _VERSIONNUM_H_

//using head files
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <regex>

//using namespace
using namespace std;

//const constants
const static char VN_OPE = '^';
const static string VN_VERSION1 = " pragma ";
const static string VN_VERSION2 = "pragma ";
const static string VN_SOLIDITY = " solidity ";
const static string VN_EXPE = " experimental ";
const static int VN_INDEX = 0;
const static char NO_MATCH = '<';

//regex
const static string VN_RE_VERSION1 = "(\\s)*(pragma)(\\s)+(solidity)(\\s)+(\\^)(\\d)(\\.)(\\d)(\\.)(\\d)+(\\s)*(;)";
const static string VN_RE_VERSION2 = "(\\s)*(pragma)(\\s)+(solidity)(\\s)+(\\>)(\\=)(\\d)(\\.)(\\d)(\\.)(\\d)+(\\s)+";
const static string VN_RE_EXPER = "(\\s)*(pragma)(\\s)+(experimental)(\\s)+";


//class version
class VersionNum {
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string VNName;
    string OtherOperation;
protected:
    bool IsPragmaSolidity(const string& _str);
    bool ContainOpe(const string& _str);
    bool IsSecurity(const string& _str);
    void AddReport();
    bool IsNewOpe(const string& _str);
public:
    //constructor
    VersionNum(const string _report_name, const vector<string> _content);
    //destructor
    ~VersionNum();
    //get detect report
    string MakeReport(vector<int> _row_number);
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

