//
// Created by xiaofeng on 2019/11/25.
//

//The program is used to detect balance equality
//for example:
/*
	if(this.balance == 42 ether){
		//todo
		}
*/
//an adversary can forcibly send ether to any account by mining or via selfdestruct.

//source file

/*
author=_xiaofeng_
*/

//using head files
#include "BalanceEquality.h"
#include <iostream>

//constructor
Balance::Balance(const string _report_name, const vector<string> _content) {
    content = _content;
    report_name = _report_name;
    BEName = "Unexpected ether balance";
    OtherOperation = "Contracts can behave erroneously when they strictly assume a specific Ether balance.\n"
                     "It is always possible to forcibly send ether to a contract (without triggering its fallback \n"
                     "function), using selfdestruct, or by mining to the account. In the worst case scenario this \n"
                     "could lead to DOS conditions that might render the contract unusable. \nBug level: error ";
}

//destructor
Balance::~Balance() {
    content.clear();
    report_name.clear();
    BEName.clear();
    OtherOperation.clear();
    row_number.clear();
}

//get report
string Balance::MakeReport(const vector<int>& _row_number) {
    if (_row_number.size() == 0) {
        return "No unexpected ether balance.\n\n";
    }
    string _report = "";
    _report += "[Bug 3]\n";
    _report += "bug name: ";
    _report += BEName;
    _report += '\n';
    _report += "number of bugs: ";
    _report += to_string(_row_number.size());
    _report += '\n';
    _report += "row number: ";
    for (auto i = _row_number.begin(); i != _row_number.end(); i++) {
        _report += to_string((*i));
        _report += " ";
    }
    _report += '\n';
    if (OtherOperation.size() != 0) {
        _report += "additional description: ";
        _report += OtherOperation;
        _report += '\n';
    }
    return _report;
}

//Balance::Detection,execute detection
void Balance::Detection() {
    for (int i = 0; i < content.size(); i++) {
        if (IfStatement(content[i])) {
            string temp = FilterBlank(content[i]);
            if (Leak(temp)) {
                row_number.push_back((i + 1));
            }
        }
        if (WhileStatement(content[i])) {
            string temp = FilterBlank(content[i]);
            if (Leak(temp)) {
                row_number.push_back((i + 1));
            }
        }
        if (ForStatement(content[i])) {
            string temp = FilterBlank(content[i]);
            if (Leak(temp)) {
                row_number.push_back((i + 1));
            }
        }
        if (RequireStatement(content[i])) {
            string temp = FilterBlank(content[i]);
            if (Leak(temp)) {
                row_number.push_back((i + 1));
            }
        }
        else
            continue;
    }
}

void Balance::Re_Detection()
{
    regex reg_if{ BE_RE_IF_WHILE_REQUIRE };
    regex reg_for{ BE_RE_FOR };
    for (int i = 0; i < content.size(); i++) {
        if (content[i].find(".balance") < content[i].size()) {
            smatch s;
            /*
            if (regex_match(content[i], s, reg_if) || regex_match(content[i], s, reg_for))
                row_number.push_back((i + 1));
            else
                continue;
            */
            if(regex_search(content[i], s, regex{BE_RE_LEFT_EQUAL1})){
                row_number.push_back((i+1));
            }
            else if(regex_search(content[i], s, regex{BE_RE_LEFT_EQUAL2})){
                row_number.push_back((i+1));
            }
            else if(regex_search(content[i], s, regex{BE_RE_RIGHT_EQUAL1})){
                row_number.push_back((i+1));
            }
            else if(regex_search(content[i], s, regex{BE_RE_RIGHT_EQUAL2})){
                row_number.push_back((i+1));
            }
            else{
                continue;
            }
        }
        else
            continue;
    }
}

//if _str is if-statement ,return true
bool Balance::IfStatement(const string& _str) {
    if ((_str.find(BE_IF1) < _str.size()) || (_str.find(BE_IF2) < _str.size()))
        return true;
    return false;
}

//if _str is while-statement ,return true
bool Balance::WhileStatement(const string& _str) {
    if ((_str.find(BE_WHILE1) < _str.size()) || (_str.find(BE_WHILE2) < _str.size()))
        return true;
    return false;
}


//if _str is for-statement ,return true
bool Balance::ForStatement(const string& _str) {
    if ((_str.find(BE_FOR1) < _str.size()) || (_str.find(BE_FOR2) < _str.size()))
        return true;
    return false;
}

//if _str is require-statement ,return true
bool Balance::RequireStatement(const string& _str) {
    if ((_str.find(BE_REQUIRE1) < _str.size()) || (_str.find(BE_REQUIRE2) < _str.size()))
        return true;
    return false;
}

//Filter blank/space in _str
string Balance::FilterBlank(const string& _str) {
    string temp = "";
    for (int i = 0; i < _str.size(); i++) {
        if (_str[i] == ' ' || _str[i] == '\t')
            continue;
        else
            temp += _str[i];
    }
    return temp;
}

//if _str contains BE_LEAK1 or BE_LEAK2,return true
//else false
bool Balance::Leak(const string& _str) {
    if ((_str.find(BE_LEAK1) < _str.size()) || (_str.find(BE_LEAK2) < _str.size()))
        return true;
    return false;
}

//return number of vulnerabilities
int Balance::GetNumber() {
    return row_number.size();
}

//return row_number
vector<int> Balance::GetRowNumber() {
    return row_number;
}
