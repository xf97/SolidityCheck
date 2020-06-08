//
// Created by xiaofeng on 2019/11/29.
//

//This program is used to judge integer division.

//source file

/*
author=__xiaofeng__
*/

//using head files
#include <iostream>
#include "IntDivision.h"

bool IntDivision::IsDivision(const string & _str)
{
    if (_str.find(ID_DIV) < _str.size())
        return true;
    return false;
}

void IntDivision::GetIndex(const string& _str,vector<int>& _index)
{
    _index.clear();
    int index = 0;
    while (_str.find(ID_DIV, index) < _str.size()) {
        index = _str.find(ID_DIV, index);
        _index.push_back(index);
        index++;
    }
}

void IntDivision::GetLeft(string & _str, int _index,const string& _sta)
{
    int _i = _index;
    _i--;
    _str.clear();
    while (isblank(_sta[_i]) && _i>=0)
        _i--;
    while (_i >= 0 && isdigit(_sta[_i])) {
        _str.push_back(_sta[_i]);
        _i--;
    }
    reverse(_str.begin(), _str.end());
}

void IntDivision::GetRight(string & _str, int _index, const string & _sta)
{
    _str.clear();
    _index++;
    while (isblank(_sta[_index]) && _index >= 0)
        _index++;
    while (isdigit(_sta[_index]) && _index>=0)
    {
        _str.push_back(_sta[_index]);
        _index++;
    }
}

bool IntDivision::IsInt(const string & _str)
{
    if (_str.empty())
        return false;
    for (auto i = _str.begin(); i != _str.end(); i++) {
        if (!isdigit((*i)))
            return false;
    }
    return true;
}

IntDivision::IntDivision(const string _report_name, const vector<string> _content)
{
    report_name = _report_name;
    content = _content;
    IDName = "Integer Division";
    OtherOperation = "All integer division results in Solidity are rounded down.\nBug level: warning";
}

IntDivision::~IntDivision()
{
    report_name.clear();
    content.clear();
    IDName.clear();
    OtherOperation.clear();
    row_number.clear();
}

string IntDivision::MakeReport(const vector<int>& _row_number)
{
    if (_row_number.size() == 0) {
        return "No integer division.\n\n";
    }
    string _report = "";
    _report += "[Bug 9]\n";
    _report += "bug name: ";
    _report += IDName;
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

int IntDivision::GetNumber()
{
    return row_number.size();
}

vector<int> IntDivision::GetRowNumber()
{
    return row_number;
}

void IntDivision::Detection()
{
    string left = "";
    string right = "";
    vector<int> index;
    for (int i = 0; i < content.size(); i++) {
        if (IsDivision(content[i])) {
            GetIndex(content[i],index);
            for (auto j = index.begin(); j != index.end(); j++) {
                GetLeft(left, (*j),content[i]);
                GetRight(right, (*j),content[i]);
                if (IsInt(left) && IsInt(right)) {
                    row_number.push_back((i + 1));
                }
            }
        }
    }
}

void IntDivision::Re_Detection()
{
    regex reg{ID_RE_DIV};
    for (int i = 0; i < content.size(); i++) {
        if (content[i].find('/') < content.size()) {
            smatch s;
            if (regex_search(content[i], s, reg)) {
                row_number.push_back(i + 1);
            }
            else
                continue;
        }
        else
            continue;
    }
}


