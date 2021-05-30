//
// Created by xiaofeng on 2020/6/6.
//

#ifndef SOLIDITYCHECK_PUBLICTOEXTERNAL_H
#define SOLIDITYCHECK_PUBLICTOEXTERNAL_H

/*
 *
 * This class is used to detect public functions that are not used in contracts, and then replace public with external
 */

//head file

//using head files
#include <vector>
#include <string>
#include <iterator>
#include <algorithm>
#include <regex>
#include <fstream>
#include <sstream>
#include <cctype>

using namespace std;

//keyword
const static string PTE_FUN = " function ";
const static string PTE_PUBLIC1 = " public ";
const static string PTE_PUBLIC2 = " public{";

//regex
//find public function (include fallback function)
const static string PTE_RE_PUBLIC_FUNCTION = "^(\\s)*(function)(\\s)+(\\w)*(\\()(.)*(\\))(\\s)+(.)*(\\b)(public)(\\b)(.)*(\\{)$";

//class publicToExternal
class publicToExternal{
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string PTEName;
    string OtherOperation;
protected:
    string getFunctionName(const string& _str); //return function name
    bool findFunction(const vector<string>& _content, const string& _functionName, int lineNumber);
    vector<string> replacePublic(vector<string> _content, vector<int> _rowNumber);
public:
    //constructor
    publicToExternal(const string _report_name, const vector<string> _content);
    //destructor
    ~publicToExternal();
    //get detect report
    string MakeReport(const vector<int>& _row_number);
    //return row_number size
    int GetNumber();
    //return row_number
    vector<int> GetRowNumber();
    //regex detection
    void Re_Detection(const string& _filename);
    //output fix contract
    void outFixContract(const vector<string> _content, const string& _filename);
    string makeNewFileName(const string& _filename);
};



#endif //SOLIDITYCHECK_PUBLICTOEXTERNAL_H
