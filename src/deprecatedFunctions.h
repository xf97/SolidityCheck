//
// Created by xiaofeng on 2020/6/8.
//

#ifndef SOLIDITYCHECK_DEPRECATEDFUNCTIONS_H
#define SOLIDITYCHECK_DEPRECATEDFUNCTIONS_H

//source file

/*
 * This part of the program is used to detect the "deprecated built in symbols" bug.
 */

//using head files
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <regex>
#include <fstream>
#include <sstream>

//namespace
using namespace std;

//const keywords
const static string DF_SUICIDE = "suicide";
const static string DF_POINT = ".";
const static string DF_BLOCK = "block";
const static string DF_BLOCKHASH = "blockhash";
const static string DF_SHA3 = "sha3";
const static string DF_CALLCODE = "callcode";
const static string DF_THROW = "throw";
const static string DF_MSG = "msg";
const static string DF_GAS = "gas";
const static string DF_CONSTANT = "constant";
const static string DF_VAR = "var";

//regex
const static string DF_RE_SUICIDE = "(\\s)(suicide)(\\s)*(\\()";
const static string DF_RE_BLOCKBLOCKHASH = "(\\s)(block)(\\s)*(\\.)(\\s)*(blockhash)(\\()";
const static string DF_RE_SHA3 = "(\\s)(sha3)(\\s)*(\\()";
const static string DF_RE_CALLCODE = "(\\.)(\\s)*(callcode)(\\s)*(\\()";
const static string DF_RE_THROW = "(\\s)(throw)(\\b)";
const static string DF_RE_MSGGAS = "(\\s)(msg)(\\s)*(\\.)(\\s)*(gas)(\\b)";
const static string DF_RE_CONSTANT = "(\\s)(constant)(\\b)";
const static string DF_RE_VAR = "(\\s)(var)(\\b)";
const static string DF_RE_FUNCTION = "(\\s)(function)(\\s)";

//class
class deprecatedFunction{
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string DFName;
    string OtherOperation;
    string referenceUrl;
protected:
    vector<string> replaceDeprecated(vector<string> _content, vector<int> _rowNumber);
public:
    //constructor
    deprecatedFunction(const string _report_name, const vector<string> _content);
    //destructor
    ~deprecatedFunction();
    //get detect report
    string MakeReport(vector<int> _row_number);
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

#endif //SOLIDITYCHECK_DEPRECATEDFUNCTIONS_H
