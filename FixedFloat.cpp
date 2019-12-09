//
// Created by xiaofeng on 2019/11/29.
//

//Solidity does not yet fully support fixed-length floating-point type.
//Fixed-length floating-point variables can be declared, but they cannot
//be assigned or assigned to other variables.

//source files

/*
author=__xiaofeng__
*/


#include "FixedFloat.h"
#include <iostream>

bool FixedFloat::OnlyFixed(const string & _str)
{
    if (_str.find(FF_FIXED1) < _str.size() || _str.find(FF_UFIXED1) < _str.size())
        return true;
    return false;
}

bool FixedFloat::ReFixed(const string & _str)
{
    string temp = "";
    int i = 0;
    while (isblank(_str[i]) && i<_str.size())
        i++;
    while (!isblank(_str[i]) && i<_str.size()) {
        temp.push_back(_str[i]);
        i++;
    }
    if (temp.find(FF_FIXED2) < temp.size() && temp.find(FF_CHEN)) {
        int lindex = temp.find(FF_FIXED2);
        lindex += 5;
        int rindex = temp.find(FF_CHEN);
        bool flag1 = true, flag2 = true;
        for (int i = lindex; i < rindex; i++) {
            if (!isdigit(temp[i])) {
                flag1 = false;
                break;
            }
        }
        for (int i = rindex + 1; i < temp.size(); i++) {
            if (!isdigit(temp[i])) {
                flag2 = false;
                break;
            }
        }
        if (flag1 == false || flag2 == false)
            return false;
        else
            return true;
    }
    else if (temp.find(FF_UFIXED2) < temp.size() && temp.find(FF_CHEN)) {
        int lindex = temp.find(FF_UFIXED2);
        lindex += 6;
        int rindex = temp.find(FF_CHEN);
        bool flag1 = true, flag2 = true;
        for (int i = lindex; i < rindex; i++) {
            if (!isdigit(temp[i])) {
                flag1 = false;
                break;
            }
        }
        for (int i = rindex + 1; i < temp.size(); i++) {
            if (!isdigit(temp[i])) {
                flag2 = false;
                break;
            }
        }
        if (flag1 == false || flag2 == false)
            return false;
        else
            return true;
    }
    else
        return false;
}

FixedFloat::FixedFloat(const string _report_name, const vector<string> _content)
{
    report_name = _report_name;
    content = _content;
    FFName = "Using fixed point number type";
    OtherOperation = "Solidity does not yet fully support fixed-length floating-point type.Fixed-length floating-point variables can be declared, but they cannot be assigned or assigned to other variables.\nVulnerability level:warning";
}

FixedFloat::~FixedFloat() {
    report_name.clear();
    content.clear();
    FFName.clear();
    OtherOperation.clear();
    row_number.clear();
}

string FixedFloat::MakeReport(const vector<int>& _row_number)
{
    if (_row_number.empty()) {
        return "No using fixed point number type.\n\n";
    }
    string _report = "";
    _report += "[Vulnerability 19]\n";
    _report += "vulnerability name: ";
    _report += FFName;
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

int FixedFloat::GetNumber() {
    return row_number.size();
}

vector<int> FixedFloat::GetRowNumber() {
    return row_number;
}

void FixedFloat::Detection()
{
    for (int i = 0; i < content.size(); i++) {
        if (OnlyFixed(content[i])) {
            row_number.push_back((i + 1));
        }
        else if (ReFixed(content[i])) {
            row_number.push_back((i + 1));
        }
        else
            continue;
    }
}

void FixedFloat::Re_Detection()
{
    regex reg{FF_RE_FLOAT};
    for (int i = 0; i < content.size(); i++) {
        if (content[i].find("fixed") < content[i].size()) {
            smatch s;
            if (regex_search(content[i], s, reg))
                row_number.push_back(i + 1);
            else
                continue;
        }
        else
            continue;
    }
}


