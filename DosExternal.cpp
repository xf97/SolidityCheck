//
// Created by xiaofeng on 2019/11/25.
//

//Do not depend on the return value of the external contract, the external
//contract may be killed. Patterns detect if/require/while/for conditional
//judgments that contain external function calls.

//source files

/*
author=__xiaofeng__
*/


#include "DosExternal.h"
#include <iostream>

bool Dos::IsRequire(const string & _str)
{
    if (_str.find(DE_REQUIRE1) < _str.size() || _str.find(DE_REQUIRE2) < _str.size())
        return true;
    return false;
}

bool Dos::IsIf(const string & _str)
{
    if (_str.find(DE_IF1) < _str.size() || _str.find(DE_IF2) < _str.size())
        return true;
    return false;
}

bool Dos::IsFor(const string & _str)
{
    if (_str.find(DE_FOR1) < _str.size() || _str.find(DE_FOR2) < _str.size())
        return true;
    return false;
}

bool Dos::IsCall(const string & _str)
{
    regex reg1{ DE_RE_REQUIRE_IF_CALL };
    regex reg2{ DE_RE_FOR_CALL };
    smatch s;
    if (regex_search(_str, s, reg1)) {
        return true;
    }
    else if (regex_search(_str, s, reg2))
        return true;
    return false;
}

bool Dos::IsWhile(const string & _str)
{
    if (_str.find("while(") < _str.size() || _str.find("while ") < _str.size())
        return true;
    return false;
}

Dos::Dos(const string _report_name, const vector<string> _content)
{
    report_name = _report_name;
    content = _content;
    DEName = "Dos by external contract.";
    OtherOperation = "Do not depend on the return value of the external contract, the external contract may be killed.\nVulnerability level:error ";
}

Dos::~Dos()
{
    report_name.clear();
    content.clear();
    DEName.clear();
    OtherOperation.clear();
    row_number.clear();
}

int Dos::GetNumber()
{
    return row_number.size();
}

vector<int> Dos::GetRowNumber()
{
    return row_number;
}

string Dos::MakeReport(const vector<int>& _row_number)
{
    if (_row_number.empty()) {
        return "No dos by external contract.\n\n";
    }
    string _report = "";
    _report += "[Vulnerability 22]\n";
    _report += "vulnerability name: ";
    _report += DEName;
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

void Dos::Detection()
{
    for (int i = 0; i < content.size(); i++) {
        if (IsRequire(content[i]) || IsIf(content[i]) || IsFor(content[i])) {
            if (IsCall(content[i])) {
                row_number.push_back((i + 1));
            }
            else
                continue;
        }
        else {
            continue;
        }
    }
}

void Dos::Re_Detection()
{
    regex reg_if{ DE_RE_REQUIRE_IF_CALL };
    regex reg_for{ DE_RE_FOR_CALL };
    for (int i = 0; i < content.size(); i++) {
        if (IsRequire(content[i]) || IsIf(content[i]) || IsFor(content[i]) || IsWhile(content[i])) {
            smatch s;
            if (regex_search(content[i], s, reg_if) || regex_search(content[i], s, reg_for))
                row_number.push_back(i + 1);
            else
                continue;
        }
        else {
            continue;
        }
    }
}


