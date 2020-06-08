//
// Created by xiaofeng on 2020/6/8.
//

#ifndef SOLIDITYCHECK_TRANSACTIONORDERDEP_H
#define SOLIDITYCHECK_TRANSACTIONORDERDEP_H

/*
 * This part of the program is used to detect "transaction order dependent" bugs.
 */

//head file
#include <vector>
#include <string>
#include <algorithm>
#include <regex>
#include <iterator>

//namespace
using namespace std;

//const keyword
const static string TOD_APPROVE = " approve";

//regex
const static string TOD_RE_APPROVE = "(\\s)*(function)(\\s)+(approve)(\\()(address)(\\s)+(\\w)+(\\s)*(\\,)(\\s)*((uint256)|(uint))(\\s)+(\\w)+(\\))(\\s)+((public)|(external))(\\s)+(returns)(\\s)*(\\()(bool)(.)*(\\))";

//class
class TransactionOrderDep{
private:
    //data
    vector<string> content;	//be detected contract's content;
    string report_name;		//report file name
    vector<int> row_number;	//code lines that may have vulnerabilities
    string TODName;
    string OtherOperation;
public:
    //constructor
    TransactionOrderDep(const string _report_name, const vector<string> _content);
    //destructor
    ~TransactionOrderDep();
    //get detect report
    string MakeReport(const vector<int>& _row_number);
    //return row_number size
    int GetNumber();
    //return row_number
    vector<int> GetRowNumber();
    //regex detection
    void Re_Detection();
};

#endif //SOLIDITYCHECK_TRANSACTIONORDERDEP_H
