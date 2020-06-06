//
// Created by xiaofeng on 2020/6/6.
//

#ifndef SOLIDITYCHECK_WRONGOPERATOR_H
#define SOLIDITYCHECK_WRONGOPERATOR_H

/*
 *This part of the program is used to fix the "wrong operator" bug.
 */

//using hear files
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <regex>
#include <fstream>
#include <sstream>

//using namespace
using namespace std;

//const string
const static string WO_ADD = "+";
const static string WO_SUB = "-";
const static string WO_EQU = "=";
//replacement
const static string WO_ADD_EQU = "+=";
const static string WO_SUB_EQU = "-=";

//regex
const static string WO_RE_EQU_ADD = "(\\=)(\\s)*(\\+)";
const static string WO_RE_EQU_SUB = "(\\=)(\\s)*(\\-)";

class wrongOperator{
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string WOName;
    string OtherOperation;
protected:
    vector<string> replaceWrongOpe(vector<string> _content, vector<int> _rowNumber);
public:
    //constructor
    wrongOperator(const string _report_name, const vector<string> _content);
    //destructor
    ~wrongOperator();
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



#endif //SOLIDITYCHECK_WRONGOPERATOR_H
