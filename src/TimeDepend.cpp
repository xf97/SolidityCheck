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
    TDName = "Block values as a proxy for time";
    OtherOperation = "In the case of block.timestamp, developers often attempt to use it to trigger \n"
                     "time-dependent events. As Ethereum is decentralized, nodes can synchronize time \n"
                     "only to some degree. Moreover, malicious miners can alter the timestamp of their \n"
                     "blocks, especially if they can gain advantages by doing so. However, miners can't \n"
                     "set a timestamp smaller than the previous one (otherwise the block will be rejected), \n"
                     "nor can they set the timestamp too far ahead in the future. Taking all of the above \n"
                     "into consideration, developers can't rely on the preciseness of the provided timestamp.\n"
                     "Bug level: warning";
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
        return "No block values as a proxy for time.\n\n";
    }
    string _report = "";
    _report += "[Bug 8]\n";
    _report += "bug name: ";
    _report += TDName;
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
        else if (content[i].find("block.number") < content[i].size()){
            regex reg1{TD_RE_BLOCKNUMBER};
            smatch  s;
            if (regex_search(content[i], s, reg1)){
                row_number.push_back((i + 1));
            }
        }
        else if (content[i].find("block.coinbase") < content[i].size()){
            regex reg2{TD_RE_COINBASE};
            smatch s;
            if (regex_search(content[i], s, reg2)){
                row_number.push_back((i+1));
            }
        }
        else if (content[i].find("block.difficulty") < content[i].size()){
            regex reg3{TD_RE_DIFFICULTY};
            smatch s;
            if(regex_search(content[i], s, reg3)){
                row_number.push_back((i+1));
            }
        }
        else if (content[i].find("blockhash") < content[i].size()){
            regex reg4{TD_RE_BLOCKHASH1};
            regex reg5{TD_RE_BLOCKHASH2};
            smatch s, s1;
            if(regex_search(content[i], s, reg5)){
                row_number.push_back((i+1));
            }
            else if(regex_search(content[i], s1, reg4)){
                row_number.push_back((i+1));
            }
        }
    }
}
