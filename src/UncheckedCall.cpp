//
// Created by xiaofeng on 2019/11/29.
//

//This program is used to detect unchecked external call vulnerabilities
//detect method:the detection method is whether the  send()/call/delegatecall()
//statements are in the if/require statemens.

//source file

/*
author=_xiaofeng_
*/

//using head files
#include <iostream>
#include "UncheckedCall.h"

//constructor
Call::Call(const string _report_name, const vector<string> _content) {
    report_name = _report_name;
    content = _content;
    UCName = "Unchecked call return value";
    OtherOperation = "The return value of a message call is not checked. Execution will resume even \n"
                     "if the called contract throws an exception. If the call fails accidentally or \n"
                     "an attacker forces the call to fail, this may cause unexpected behaviour in the\n"
                     " subsequent program logic.\nBug level:error ";
}

//destructor
Call::~Call() {
    report_name.clear();
    content.clear();
    UCName.clear();
    OtherOperation.clear();
    row_number.clear();
}

//make detection report
string Call::MakeReport(const vector<int>& _row_number) {
    if (_row_number.empty()) {
        return "No unchecked call return value.\n\n";
    }
    string _report = "";
    _report += "[Bug 4]\n";
    _report += "bug name: ";
    _report += UCName;
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

//execute detection
void Call::Detection() {
    for (int i = 0; i < content.size(); i++) {
        if (IsExternal(content[i])) {
            if (IsInIf(content[i])) {
                continue;
            }
            else if (IsInRequire(content[i])) {
                continue;
            }
            else
                row_number.push_back((i + 1));
        }
    }

}

void Call::Re_Detection()
{
    regex reg{ UC_RE_IF };
    for (int i = 0; i < content.size(); i++) {
        if (IsExternal(content[i])) {
            smatch s;
            if (regex_search(content[i], s, reg))
                continue;
            else
                row_number.push_back((i + 1));
        }
    }

}

//if statements is external call,return true
//else return false
bool Call::IsExternal(const string& _str) {
    if (IsCall(_str) || IsDele(_str) || IsSend(_str) || IsCallCode(_str))
        return true;
    return false;
}

//if statement is in if-statement,return true
//else return false
bool Call::IsInIf(const string& _str) {
    if (_str.find(UC_IF1) < _str.size() || _str.find(UC_IF2) < _str.size())
        return true;
    return false;
}

//if statement is in require-statement ,return true
//else return false
bool Call::IsInRequire(const string& _str) {
    if (_str.find(UC_REQUIRE1) < _str.size() || _str.find(UC_REQUIRE2) < _str.size())
        return true;
    return false;
}

//if statement contains .call(),return true
//else return false
bool Call::IsCall(const string& _str) {
    if (_str.find(UC_CALL1) < _str.size() || _str.find(UC_CALL2) < _str.size() || _str.find(UC_CALL3) < _str.size())
        return true;
    return false;
}

//if statement contains .delegatecall(),return true
//else return false
bool Call::IsDele(const string& _str) {
    if (_str.find(UC_DELE1) < _str.size() || _str.find(UC_DELE2) < _str.size() || _str.find(UC_DELE3) < _str.size())
        return true;
    return false;
}

//if statement contains .send(),return true
//else return false
bool Call::IsSend(const string& _str) {
    if (_str.find(UC_SEND1) < _str.size() || _str.find(UC_SEND2) < _str.size())
        return true;
    return false;
}

bool Call::IsCallCode(const string & _str)
{
    if (_str.find(UC_CALLCODE1) < _str.size() || _str.find(UC_CALLCODE2) < _str.size() || _str.find(UC_CALLCODE3)<_str.size())
        return true;
    return false;
}

//return number of vulnerabilities
int Call::GetNumber() {
    return row_number.size();
}

//return row_number
vector<int> Call::GetRowNumber() {
    return row_number;
}