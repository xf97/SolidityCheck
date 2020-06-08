//
// Created by xiaofeng on 2019/11/29.
//

//This part of the program is used to detect version number problems.
//Using operators or unspecified security specifications can lead to
//unexpected consequences.

//source file

/*
author=__xiaofeng__
*/

//using head files
#include <iostream>
#include "VersionNum.h"

//constructor
VersionNum::VersionNum(const string _report_name, const vector<string> _content) {
    report_name = _report_name;
    content = _content;
    VNName = "Floating pragma";
    OtherOperation = "Contracts should be deployed with the same compiler version and flags \n"
                     "that they have been tested with thoroughly. Locking the pragma helps to\n"
                     " ensure that contracts do not accidentally get deployed using, for example,\n"
                     " an outdated compiler version that might introduce bugs that affect the \n"
                     "contract system negatively.\nBug level: warning";
}

//destructor
VersionNum::~VersionNum() {
    report_name.clear();
    content.clear();
    VNName.clear();
    OtherOperation.clear();
    row_number.clear();
}

//make detect report
string VersionNum::MakeReport(vector<int> _row_number) {
    //Are security specifications specified for use?
    bool security = false;
    for (int i = 0; i < content.size(); i++) {
        if (IsSecurity(content[i])) {
            security = true;
        }
    }
    if (security == false) {
        AddReport();
    }

    if (_row_number.size() == 0 && security == true) {
        return "No floating pragma.\n\n";
    }
    else if (_row_number.size() == 0 && security == false) {
        row_number.push_back(1);
        _row_number.push_back(1);
    }
    string _report = "";
    _report += "[Bug 7]\n";
    _report += "bug name: ";
    _report += VNName;
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
void VersionNum::Detection() {
    bool pragma = false;
    //Whether version operator '^' are used
    for (int i = 0; i < content.size(); i++) {
        if (IsPragmaSolidity(content[i])) {
            pragma = true;
            if (ContainOpe(content[i])) {
                row_number.push_back((i + 1));
            }
            else if (IsNewOpe(content[i]))
                row_number.push_back((i + 1));
            else
                continue;
        }
    }
    if (!pragma) {
        row_number.push_back((1));
    }
}

//if _str is pragma-statement,return true
//else return false
bool VersionNum::IsPragmaSolidity(const string& _str) {
    if (_str.find(VN_VERSION1) < _str.size() && _str.find(VN_SOLIDITY) < _str.size())
        return true;
    else if (_str.find(VN_VERSION2) < _str.size() && _str.find(VN_SOLIDITY) < _str.size() && (_str.find(VN_VERSION2) == VN_INDEX))
        return true;
    else
        return false;
}

//if _str contains '^',return true
//else return false
bool VersionNum::ContainOpe(const string& _str) {
    if (_str.find(VN_OPE) < _str.size())
        return true;
    return false;
}

//if _str is security-statement,return true
//else return false
bool VersionNum::IsSecurity(const string& _str) {
    if (_str.find("pragma") < _str.size() && _str.find(VN_EXPE) < _str.size()) {
        regex reg{ VN_RE_EXPER };
        smatch s;
        if (regex_search(_str, s, reg))
            return true;
        else
            return false;
    }
    return false;
}

//add string into OtherOperation
void VersionNum::AddReport() {
    OtherOperation += ("\nAttention: Add the following statement to indicate the version of the security specification used: pragma experimental \"vCompiler Version\"");
}

bool VersionNum::IsNewOpe(const string & _str)
{
    if (_str.find('>') < _str.size() && _str.find('=') < _str.size() && _str.find('<') >= _str.size())
        return true;
    return false;
}

//return number of vulnerabilities
int VersionNum::GetNumber() {
    return row_number.size();
}

//return row_number
vector<int> VersionNum::GetRowNumber() {
    return row_number;
}

void VersionNum::Re_Detection()
{
    bool pragma = false;
    //Whether version operator '^' are used
    for (int i = 0; i < content.size(); i++) {
        if (IsPragmaSolidity(content[i])) {
            pragma = true;
            if (ContainOpe(content[i])) {
                regex reg_v1{ VN_RE_VERSION1 };
                smatch s;
                if (regex_search(content[i], s, reg_v1))
                    row_number.push_back(i + 1);
            }
            else if (IsNewOpe(content[i])) {
                row_number.push_back(i + 1);
            }
            else
                continue;
        }
    }
    if (!pragma) {
        row_number.push_back((1));
    }
}
