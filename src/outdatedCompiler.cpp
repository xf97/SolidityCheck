//
// Created by xiaofeng on 2020/6/6.
//

#include "outdatedCompiler.h"
#include <iostream>

outdatedCompiler::outdatedCompiler(const string _report_name, const vector<string> _content) {
    report_name = _report_name;
    content = _content;
    OCName = "Outdated Compiler Version";
    OtherOperation = "Using an outdated compiler version can be problematic especially if there are publicly disclosed bugs and issues that affect the current compiler version.\nVulnerability level:warning";
    standard = "0.4.24";
}

outdatedCompiler::~outdatedCompiler() {
    report_name.clear();
    content.clear();
    OCName.clear();
    OtherOperation.clear();
    standard.clear();
    row_number.clear();
}

string outdatedCompiler::MakeReport(vector<int> _row_number) {
    if (_row_number.empty()) {
        return "No outdated compiler version.\n\n";
    }
    string _report = "";
    _report += "[Bug 21]\n";
    _report += "bug name: ";
    _report += OCName;
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

int outdatedCompiler::GetNumber() {
    return  row_number.size();
}

vector<int> outdatedCompiler:: GetRowNumber() {
    return row_number;
}

bool outdatedCompiler::IsPragmaSolidity(const string &_str) {
    return _str.find(OC_PRAGMA) < _str.size() && _str.find(OC_SOLIDITY) < _str.size() &&
           _str.find(OC_FENHAO) < _str.size();
}

void outdatedCompiler::Re_Detection() {
    regex version1{OC_RE_VERSION1};
    regex version2{OC_RE_VERSION2};
    //bool existFlag = false;
    for (int i = 0; i < content.size(); i++){
        if(IsPragmaSolidity(content[i])){
            smatch s;
            smatch s1;
            if(regex_search(content[i], s, version1)){
                //existFlag = true;
                string nowVersion = getVersion(content[i]);
                if(nowVersion <= standard){
                    row_number.push_back((i+1));
                }
            }
            else if(regex_search(content[i], s1, version2)){
                string nowVersion = getVersion(content[i]);
                if(nowVersion <= standard){
                    row_number.push_back((i+1));
                }
            }
        }
        else{
            continue;
        }
    }
    //if (existFlag == false)
}

string outdatedCompiler::getVersion(const string &_str) {
    regex reg{OC_RE_GET_VERSION};
    smatch result;
    if(regex_search(_str, result, reg)){
        return result[0];
    }
    return "0.4.24";
}


