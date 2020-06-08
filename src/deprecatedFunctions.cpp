//
// Created by xiaofeng on 2020/6/8.
//

#include "deprecatedFunctions.h"
#include <iostream>

deprecatedFunction::deprecatedFunction(const string _report_name, const vector<string> _content) {
    report_name = _report_name;
    content = _content;
    DFName = "Use of deprecated solidity functions";
    referenceUrl = "https://swcregistry.io/docs/SWC-111";
    OtherOperation = "Several functions and operators in Solidity are deprecated. \n"
                     "Using them leads to reduced code quality. With new major versions\n"
                     "of the Solidity compiler, deprecated functions and operators may\n"
                     "result in side effects and compile errors. Please refer to " + referenceUrl + " for details.\nBug level: warning";
}

deprecatedFunction::~deprecatedFunction() {
    report_name.clear();
    content.clear();
    DFName.clear();
    referenceUrl.clear();
    OtherOperation.clear();
    row_number.clear();
}

int deprecatedFunction::GetNumber() {
    return row_number.size();
}

vector<int> deprecatedFunction::GetRowNumber() {
    return row_number;
}

string deprecatedFunction::MakeReport(vector<int> _row_number) {
    if (_row_number.empty()) {
        return "No use of deprecated solidity functions.\n\n";
    }
    string _report = "";
    _report += "[Bug 22]\n";
    _report += "bug name: ";
    _report += DFName;
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

void deprecatedFunction::Re_Detection(const string& _filename) {
    for (int i = 0; i < content.size(); i++) {
        if (content[i].find(DF_SUICIDE) < content[i].size()){
            regex reg{DF_RE_SUICIDE};
            smatch s;
            if (regex_search(content[i], s, reg)){
                row_number.push_back((i+1));
            }
        }
        else if (content[i].find(DF_BLOCK) < content[i].size() && content[i].find(DF_POINT) < content[i].size() && content[i].find(DF_BLOCKHASH) < content[i].size()){
            regex reg{DF_RE_BLOCKBLOCKHASH};
            smatch s;
            if (regex_search(content[i], s, reg)){
                row_number.push_back((i+1));
            }
        }
        else if (content[i].find(DF_SHA3) < content[i].size()){
            regex reg{DF_RE_SHA3};
            smatch s;
            if (regex_search(content[i], s, reg)){
                row_number.push_back((i+1));
            }
        }
        else if (content[i].find(DF_CALLCODE) < content[i].size()){
            regex reg{DF_RE_CALLCODE};
            smatch s;
            if (regex_search(content[i], s, reg)){
                row_number.push_back((i+1));
            }
        }
        else if (content[i].find(DF_THROW) < content[i].size()){
            regex reg{DF_RE_THROW};
            smatch s;
            if (regex_search(content[i], s, reg)){
                row_number.push_back((i+1));
            }
        }
        else if (content[i].find(DF_MSG) < content[i].size() && content[i].find(DF_POINT) < content[i].size() && content[i].find(DF_GAS) < content[i].size()){
            regex reg{DF_RE_MSGGAS};
            smatch s;
            if (regex_search(content[i], s, reg)){
                row_number.push_back((i+1));
            }
        }
        else if (content[i].find(DF_CONSTANT) < content[i].size()){
            regex reg{DF_RE_CONSTANT};
            smatch s;
            if (regex_search(content[i], s, reg)){
                row_number.push_back((i+1));
            }
        }
        else if(content[i].find(DF_VAR) < content[i].size()){
            regex reg{DF_RE_VAR};
            smatch s;
            if (regex_search(content[i], s, reg)){
                row_number.push_back((i+1));
            }
        }
        else{
            continue;
        }
    }
    if(!row_number.empty()) {
        //fix the kind of bugs
        vector<string> new_content = replaceDeprecated(content, row_number);
        //output
        outFixContract(new_content, _filename);
    }
}

void deprecatedFunction::outFixContract(const vector<string> _content, const string &_filename) {
    string new_content = "";
    string new_fileName = makeNewFileName(_filename);
    for (string i: _content){
        new_content += i;
    }
    ofstream outFile(new_fileName.c_str());
    outFile << new_content;
    outFile.close();
    cout << "Contract (fix use of deprecated solidity functions bug) generation completed.\n";
}

string deprecatedFunction::makeNewFileName(const string &_filename) {
    //find .sol
    int right_index = _filename.find(".sol");
    int left_index = right_index;
    //find the last /
    while(left_index >= 0){
        if(_filename[left_index]!='/' && _filename[left_index] != '\\'){
            left_index --;
            continue;
        }
        else{
            break;
        }
    }
    //get contract file name
    string new_filename = "NoUseDeprecatedFunctions_" + _filename.substr(left_index+1);
    //return new file name
    return _filename.substr(0,left_index+1) + new_filename;
}

vector<string> deprecatedFunction::replaceDeprecated(vector<string> _content, vector<int> _rowNumber) {
    vector<string> new_content;
    for (int i = 0; i<_content.size(); i++){
        if(count(_rowNumber.begin(), _rowNumber.end(), i+1)){
            smatch s;
            if(regex_search(content[i], s, regex{DF_RE_SUICIDE})){
                new_content.push_back(regex_replace(_content[i], regex{DF_RE_SUICIDE}, " selfdestruct(") + "\n");
            }
            else if (regex_search(content[i], s, regex{DF_RE_BLOCKBLOCKHASH})){
                new_content.push_back(regex_replace(_content[i], regex{DF_RE_BLOCKBLOCKHASH}, " blockhash(") + "\n");
            }
            else if (regex_search(content[i], s, regex{DF_RE_SHA3})) {
                new_content.push_back(regex_replace(_content[i], regex{DF_RE_SHA3}, " keccak256(") + "\n");
            }
            else if (regex_search(content[i], s, regex{DF_RE_CALLCODE})){
                new_content.push_back(regex_replace(_content[i], regex{DF_RE_CALLCODE}, " delegatecall(") + "\n");
            }
            else if (regex_search(content[i], s, regex{DF_RE_THROW})){
                new_content.push_back(regex_replace(_content[i], regex{DF_RE_THROW}, " revert(") + "\n");
            }
            else if (regex_search(content[i], s, regex{DF_RE_MSGGAS})){
                new_content.push_back(regex_replace(_content[i], regex{DF_RE_MSGGAS}, " gasleft()") + "\n");
            }
            else if (regex_search(content[i], s, regex{DF_RE_CONSTANT})){
                new_content.push_back(regex_replace(_content[i], regex{DF_RE_CONSTANT}, " view") + "\n");
            }
        }
        else{
            new_content.push_back(_content[i] + "\n");
            continue;
        }
    }
    return new_content;
}
