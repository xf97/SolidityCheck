//
// Created by xiaofeng on 2019/11/29.
//

//This part of the procedure is used to detect contracts that can accept
//external transfers but cannot be transferred.

//source file

/*
author=__xiaofeng__
*/


//using head file
#include "LockedMoney.h"
#include <iostream>

bool LockedMoney::IsAssembly_Transfer(const string & _str)
{
    if (_str.find("delegatecall") < _str.size()) {
        regex reg{ "(\\b)(delegatecall)(\\s)*(\\()" };
        smatch s;
        if (regex_search(_str, s, reg))
            return true;
    }
    else if (_str.find("staticcall") < _str.size()) {
        regex reg{ "(\\b)(staticcall)(\\s)*(\\()" };
        smatch s;
        if (regex_search(_str, s, reg))
            return true;
    }
    else if (_str.find("callvalue") < _str.size()) {
        regex reg{ "(\\b)(callvalue)(\\s)*(\\()" };
        smatch s;
        if (regex_search(_str, s, reg))
            return true;
    }
    else if (_str.find("call") < _str.size()) {
        regex reg{ "(\\b)(call)(\\s)*(\\()" };
        smatch s;
        if (regex_search(_str, s, reg))
            return true;
    }
    return false;
}

bool LockedMoney::IsAssembly(const string & _str)
{
    if (_str.find("assembly") > _str.size())
        return false;
    regex reg{ LM_ASSEMBLY };
    smatch s;
    if (regex_search(_str, s, reg))
        return true;
    return false;
}

bool LockedMoney::IsPayable(const string & _str)
{
    if (_str.find(LM_PAY) < _str.size())
        return true;
    return false;
}

bool LockedMoney::IsSend(const string & _str)
{
    if (_str.find(LM_SEND) < _str.size() || _str.find(".send ")<_str.size())
        return true;
    return false;
}

bool LockedMoney::IsTransfer(const string & _str)
{
    if (_str.find(LM_TRANSFER) < _str.size() || _str.find(".transfer ")<_str.size())
        return true;
    return false;
}

bool LockedMoney::IsCallValue(const string & _str)
{
    if (_str.find(LM_CALLVALUE) < _str.size())
        return true;
    return false;
}

LockedMoney::LockedMoney(const string _report_name, const vector<string> _content)
{
    report_name = _report_name;
    content = _content;
    LMName = "Locked Money";
    OtherOperation = "Contracts that receive external transfers should have at least one export for the transfer of ether.\nVulnerability level:error";
    flag = false;
}

LockedMoney::~LockedMoney()
{
    report_name.clear();
    content.clear();
    LMName.clear();
    OtherOperation.clear();
    row_number.clear();
}

string LockedMoney::MakeReport(const vector<int>& _row_number)
{
    if (flag==false) {
        return "No locked money.\n\n";
    }
    string _report = "";
    _report += "[Vulnerability 14]\n";
    _report += "vulnerability name: ";
    _report += LMName;
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

int LockedMoney::GetNumber()
{
    return row_number.size();
}

vector<int> LockedMoney::GetRowNumber()
{
    return row_number;
}

void LockedMoney::Detection()
{
    for (int i = 0; i < content.size(); i++) {
        if (IsPayable(content[i])) {
            row_number.push_back((i + 1));
            flag = true;
            break;
        }
    }
    if (flag == false)
        return;
    else {
        for (int i = 0; i < content.size(); i++) {
            if (IsSend(content[i]) || IsTransfer(content[i]) || IsCallValue(content[i])) {
                flag = false;
                break;
            }
        }
    }
}

void LockedMoney::Re_Detection(LM_Match& lm_ma)
{
    bool assembly_flag = false;
    regex reg_fun{LM_RE_MONEY};
    for (int i = 0; i < content.size(); i++) {
        if (IsPayable(content[i])) {
            smatch s;
            if (regex_search(content[i],s,reg_fun)) {
                row_number.push_back((i + 1));
                flag = true;
                break;
            }
        }
    }
    if (flag == false)
        return;
    else {
        regex reg1{LM_RE_TRAN_SEND};
        regex reg2{LM_RE_CALL};
        for (int i = 0; i < content.size(); i++) {
            if (IsSend(content[i]) || IsTransfer(content[i]) || content[i].find(".call.")<content[i].size()) {
                smatch s;
                if (regex_search(content[i], s, reg1) || regex_search(content[i], s, reg2)) {
                    flag = false;
                    break;
                }
            }
            else if (IsAssembly(content[i])) {
                assembly_flag = true;
            }
            else
                continue;
        }
    }
    if (flag == true && assembly_flag == true) {
        for (int i = 0; i < content.size(); ) {
            if (IsAssembly(content[i])) {
                lm_ma.Reset();
                int j = i;
                while (!lm_ma.IsMatch()) {
                    if (IsAssembly_Transfer(content[j])) {
                        flag = false;
                        break;
                    }
                    else
                        lm_ma.Match(content[j++]);
                }
                i = j;
            }
            else
                i++;
        }
    }
}

void LM_Match::Match(const string & _str)
{
    for (char c : _str) {
        if (c == '{') {
            count++;
            brackets.push_back('{');
        }
        else if (c == '}') {
            brackets.pop_back();
        }
    }
}
