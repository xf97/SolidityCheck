//
// Created by xiaofeng on 2020/6/6.
//

#ifndef SOLIDITYCHECK_OUTDATEDCOMPILER_H
#define SOLIDITYCHECK_OUTDATEDCOMPILER_H

//This part of the program is used to detect the "outdated compiler version" bug

//head file

//using head files
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <regex>

//using namespace
using namespace std;

//const static
const static string OC_PRAGMA = "pragma";
const static string OC_SOLIDITY = "solidity";
const static string OC_FENHAO = ";";

//regex
const static string OC_RE_VERSION1 = "(\\s)*(pragma)(\\s)+(solidity)(\\s)+(.)*(\\d)(\\.)(\\d)(\\.)(\\d)+(\\s)*(;)";
const static string OC_RE_VERSION2 = "(\\s)*(pragma)(\\s)+(solidity)(\\s)+(\\>)(\\=)(\\d)(\\.)(\\d)(\\.)(\\d)+(\\s)+";
const static string OC_RE_GET_VERSION = "(\\d)(\\.)(\\d)(.)(\\d)+";

class outdatedCompiler{
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string OCName;
    string OtherOperation;
    string standard;
protected:
    bool IsPragmaSolidity(const string& _str);
    string getVersion(const string& _str);
public:
    //constructor
    outdatedCompiler(const string _report_name, const vector<string> _content);
    //destructor
    ~outdatedCompiler();
    //get detect report
    string MakeReport(vector<int> _row_number);
    //return row_number size
    int GetNumber();
    //return row_number
    vector<int> GetRowNumber();
    //regex detection
    void Re_Detection();
};

#endif //SOLIDITYCHECK_OUTDATEDCOMPILER_H
