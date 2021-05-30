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
    DEName = "DoS with failed call";
    OtherOperation = "External calls can fail accidentally or deliberately, which can cause a DoS condition in the contract.\n"
                     "To minimize the damage caused by such failures, it is better to isolate each external call into its own\n"
                     "transaction that can be initiated by the recipient of the call. This is especially relevant for payments,\n"
                     "where it is better to let users withdraw funds rather than push funds to them automatically (this also\n"
                     "reduces the chance of problems with the gas limit).\nBug level: warning";
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
        return "No dos by failed call.\n\n";
    }
    string _report = "";
    _report += "[Bug 17]\n";
    _report += "bug name: ";
    _report += DEName;
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


