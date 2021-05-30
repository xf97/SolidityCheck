//
// Created by xiaofeng on 2019/11/29.
//

//This program is used to detect statements
//that may introduce reentry vulnerabilities

//source file

/*
author=__xiaofeng__
*/

//using head files
#include "Reentrant.h"
#include <iostream>
#include <iomanip>

string Reentrant::ProcessBar(const int _rate)
{
    int star = 20 * _rate / 100;
    int line = 20 - star;
    string bar = "[";
    while (star > 0) {
        bar.push_back('*');
        star--;
    }
    bar += "->";
    while (line > 0) {
        bar.push_back('.');
        line--;
    }
    bar += ']';
    return bar;
}

//Reentrant::constructor
Reentrant::Reentrant(const string _report_name, const vector<string> _content) {
    report_name = _report_name;
    content = _content;
    ReName = "Re-entrancy";
    OtherOperation = "A test contract based on code analysis is generated, which is based on your contract and inserts probe code into the contract to detect reentry vulnerabilities. We also generate a deployment file for you to deploy the contract to the truffle private chain.\nVulnerability level:error";
}

//Reentrant::destructor
Reentrant::~Reentrant() {
    report_name.clear();
    content.clear();
    row_number.clear();
    ReName.clear();
    OtherOperation.clear();
}

//Reentrant::Detection,detect reentry vulnerabilities
void Reentrant::Detection() {
    cout << "-----Start detecting-----\n";
    for (int i = 0; i < content.size(); i++) {
        double rate = (double)(i + 1) / (content.size());
        cout << "\r" << setiosflags(ios::fixed) << setprecision(0) << (rate * 100) << "%" << ProcessBar(int(rate * 100));
        if (content[i].find(REKEY) < content[i].size() && content[i].find(".gas")>content[i].size())
            row_number.push_back((i + 1));
        else
            continue;
    }
    cout << endl;
}

void Reentrant::Re_Detection()
{
    regex reg{ RE_RE_CALL };
    regex reg1{ RE_RE_CALL1 };
    //regex reg1{ "(\\.)call(\\.)value(\\()(.)+(\\))(\\()"};
    cout << "-----Start detecting-----\n";
    for (int i = 0; i < content.size(); i++) {
        double rate = (double)(i + 1) / (content.size());
        cout << "\r" << setiosflags(ios::fixed) << setprecision(0) << (rate * 100) << "%" << ProcessBar(int(rate * 100));
        if (content[i].find(REKEY) < content[i].size()) {
            smatch s;
            smatch s1;
            if ( regex_search(content[i], s, reg) || regex_search(content[i], s1, reg1)) {
                row_number.push_back(i + 1);
            }
            else
                continue;
        }
        else
            continue;
    }
    cout << endl;
    if (row_number.empty())
        return;
    else {
        cout << "-----Insert line number-----\n";
        for (auto i = row_number.begin(); i != row_number.end(); i++)
            cout << "line " << (*i) << endl;
    }
}

//Reentrant::IsReentrant,if vector<int>.size==0,there is no reentry vulnerabilities
//but if not ,there is
bool Reentrant::IsReentrant(const vector<int>& _row_number) {
    if (_row_number.size() == 0)
        return false;
    return true;
}

//Reentrant::MakeReport,this function is used to stitch strings
string Reentrant::MakeReport(const vector<int>& _row_number) {
    if (_row_number.empty())
        return "No Re-entrancy.\n\n";
    string _report = "";
    _report += "[Vulnerability 1]\n";
    _report += "vulnerability name: ";
    _report += ReName;
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

//return number of vulnerabilities
int Reentrant::GetNumber() {
    return row_number.size();
}


//return row_number
vector<int> Reentrant::GetRowNumber() {
    return row_number;
}