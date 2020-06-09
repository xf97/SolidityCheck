//
// Created by xiaofeng on 2020/6/6.
//

#include "wrongOperator.h"
#include <iostream>

//source file

wrongOperator::wrongOperator(const string _report_name, const vector<string> _content) {
    report_name = _report_name;
    content = _content;
    WOName = "Typographical error";
    OtherOperation = "Users can use =+ and =- operators in the integer operation\n"
                     "without compiling errors (up to and including version 0.4.26)\nBug level: error";
}

wrongOperator::~wrongOperator() {
    report_name.clear();
    content.clear();
    WOName.clear();
    OtherOperation.clear();
    row_number.clear();
}

string wrongOperator::MakeReport(const vector<int> &_row_number) {
    if (_row_number.empty()) {
        return "No typographical error.\n\n";
    }
    string _report = "";
    _report += "[Bug 20]\n";
    _report += "bug name: ";
    _report += WOName;
    _report += '\n';
    _report += "number of bugs: ";
    _report += to_string(_row_number.size());
    _report += '\n';
    _report += "row number: ";
    for (int i : _row_number) {
        _report += to_string(i);
        _report += " ";
    }
    _report += '\n';
    if (!OtherOperation.empty()) {
        _report += "additional description: ";
        _report += OtherOperation;
        _report += '\n';
    }
    return _report;
}


int wrongOperator::GetNumber() {
    return row_number.size();
}

vector<int> wrongOperator::GetRowNumber() {
    return row_number;
}

void wrongOperator::Re_Detection(const string &_filename) {
    regex reg{ WO_RE_EQU_ADD };
    regex reg1{WO_RE_EQU_SUB};
    for (int i = 0; i < content.size(); i++) {
        if ((content[i].find(WO_EQU) < content[i].size()) && (content[i].find(WO_ADD) < content[i].size() || content[i].find(WO_SUB) < content[i].size())){
            smatch s;
            smatch s1;
            if(regex_search(content[i], s, reg)){
                row_number.push_back((i+1));
            }
            else if(regex_search(content[i], s1, reg1)){
                row_number.push_back((i+1));
            }
        }
        else
            continue;
    }
    if(!row_number.empty()) {
        //fix the kind of bugs
        vector<string> new_content = replaceWrongOpe(content, row_number);
        //output
        outFixContract(new_content, _filename);
    }
}

void wrongOperator::outFixContract(const vector<string> _content, const string &_filename) {
    string new_content = "";
    string new_fileName = makeNewFileName(_filename);
    for (string i: _content){
        new_content += i;
    }
    ofstream outFile(new_fileName.c_str());
    outFile << new_content;
    outFile.close();
    //cout << "Contract (fix wrong operator bugs) generation completed.\n";
}

string wrongOperator::makeNewFileName(const string &_filename) {
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
    string new_filename = "NoWrongOperator_" + _filename.substr(left_index+1);
    //return new file name
    return _filename.substr(0,left_index+1) + new_filename;
}

vector<string> wrongOperator::replaceWrongOpe(vector<string> _content, vector<int> _rowNumber) {
    vector<string> new_content;
    for (int i = 0; i<_content.size(); i++){
        if(count(_rowNumber.begin(), _rowNumber.end(), i+1)){
            smatch s;
            if(regex_search(content[i], s, regex{WO_RE_EQU_ADD})){
                //=+
                new_content.push_back(regex_replace(_content[i], regex{WO_RE_EQU_ADD}, WO_ADD_EQU) + "\n");
            }
            else if(regex_search(content[i], s, regex{WO_RE_EQU_SUB})){
                //=-
                new_content.push_back(regex_replace(_content[i], regex{WO_RE_EQU_SUB}, WO_SUB_EQU) + "\n");
            }
        }
        else{
            new_content.push_back(_content[i] + "\n");
            continue;
        }
    }
    return new_content;
}