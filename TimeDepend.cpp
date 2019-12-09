//
// Created by xiaofeng on 2019/11/29.
//

//Timestamp may be affected to some extent by miners. Depending on time stamp,
//miners will gain unfair competitive advantage.

//source file

/*
author=__xiaofeng__
*/

//using head files
#include "TimeDepend.h"
#include <iostream>

//constructor
TimeDep::TimeDep(const string _report_name, const vector<string> _content) {
    report_name = _report_name;
    content = _content;
    TDName = "Timestamp dependence.";
    OtherOperation = "Timestamp may be affected to some extent by miners. Depending on time stamp, miners will gain unfair competitive advantage.\nVulnerability level:warning";
}


//destructor
TimeDep::~TimeDep() {
    report_name.clear();
    content.clear();
    TDName.clear();
    OtherOperation.clear();
    row_number.clear();
}

//get detect report
string TimeDep::MakeReport(const vector<int>& _row_number) {
    if (_row_number.empty()) {
        return "No time dependence.\n\n";
    }
    string _report = "";
    _report += "[Vulnerability 10]\n";
    _report += "vulnerability name: ";
    _report += TDName;
    _report += '\n';
    _report += "number of vulnerabilities: ";
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
void TimeDep::Detection() {
    for (int i = 0; i < content.size(); i++) {
        if (IsTime(content[i])) {
            row_number.push_back((i + 1));
        }
    }
}

//if _str exists time dependence,return true;
//else return false
bool TimeDep::IsTime(const string& _str) {
    if (_str.find(TD_BLOCK) < _str.size())
        return true;
    else if (GetIdentifier(_str))
        return true;
    else
        return false;
}

//if "now" exists in _str,return true;
//else return false.
bool TimeDep::GetIdentifier(const string& _str) {
    string temp = "";
    for (int i = 0; i < _str.size(); i++) {
        if (isalnum(_str[i]) || _str[i] == '_')
            temp += _str[i];
        else {
            if (temp == TD_NOW)
                return true;
            temp = "";
        }
    }
    return false;
}

//return number of vulnerabilities
int TimeDep::GetNumber() {
    return row_number.size();
}

//return row_number
vector<int> TimeDep::GetRowNumber() {
    return row_number;
}

void TimeDep::Re_Detection()
{
    regex reg{ TD_RE_TIME };
    for (int i = 0; i < content.size(); i++) {
        if (content[i].find("now") < content[i].size() || content[i].find("block.timestamp") < content[i].size()) {
            smatch s;
            if (regex_search(content[i], s, reg)) {
                row_number.push_back(i + 1);
            }
        }
    }
}
