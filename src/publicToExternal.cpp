//
// Created by xiaofeng on 2020/6/6.
//

#include "publicToExternal.h"
#include <iostream>

//source file

//constructor
publicToExternal::publicToExternal(const string _report_name, const vector<string> _content) {
    report_name = _report_name;
    content = _content;
    PTEName = "Public function that could be declared as external";
    OtherOperation = "Unused public functions in contracts can be declared external, which can reduce gas consumption.\nBug level: warning";
}

//destructor
publicToExternal::~publicToExternal() {
    report_name.clear();
    content.clear();
    PTEName.clear();
    OtherOperation.clear();
    row_number.clear();
}

//publicToExternal::MakeReport,stitching test results
string publicToExternal::MakeReport(const vector<int> &_row_number) {
    if (_row_number.empty()) {
        return "No public function that could be declared as external.\n\n";
    }
    string _report = "";
    _report += "[Bug 19]\n";
    _report += "bug name: ";
    _report += PTEName;
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

int publicToExternal::GetNumber() {
    return row_number.size();
}

vector<int> publicToExternal::GetRowNumber() {
    return row_number;
}

void publicToExternal::Re_Detection(const string& _filename) {
    regex reg{ PTE_RE_PUBLIC_FUNCTION };
    for (int i = 0; i < content.size(); i++) {
        if ((content[i].find(PTE_FUN) < content[i].size()) && (content[i].find(PTE_PUBLIC1) < content[i].size() || content[i].find(PTE_PUBLIC2) < content[i].size())){
            smatch s;
            if(regex_search(content[i], s, reg)){
                //find a public function
                //1.  get function name
                string functionName = getFunctionName(content[i]);
                if(!findFunction(content, functionName, i+1)){
                    //find unused public function
                    row_number.push_back((i+1));
                }
            }
        }
        else
            continue;
    }
    if(!row_number.empty()) {
        //fix the kind of bugs
        vector<string> new_content = replacePublic(content, row_number);
        //output
        outFixContract(new_content, _filename);
    }
}

void publicToExternal::outFixContract(const vector<string> _content, const string &_filename) {
    string new_content = "";
    string new_fileName = makeNewFileName(_filename);
    for (string i: _content){
        new_content += i;
    }
    ofstream outFile(new_fileName.c_str());

    outFile << new_content;
    outFile.close();
    //cout << "Contract (fix public function that could be declared as external bugs) generation completed.\n";
}

string publicToExternal::makeNewFileName(const string& _filename) {
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
    string new_filename = "NoPublicToExternal_" + _filename.substr(left_index+1);
    //return new file name
    return _filename.substr(0,left_index+1) + new_filename;
}

string publicToExternal::getFunctionName(const string &_str) {
    //get left index
    int left_index = _str.find("function ") + 9;
    while(isblank(_str[left_index])){
        left_index++;
    }
    //right index
    int right_index = left_index;
    while(isalnum(_str[right_index]) || _str[right_index] == '_'){
        right_index++;
    }
    return _str.substr(left_index, right_index -left_index);
}

bool publicToExternal::findFunction(const vector<string> &_content, const string &_functionName, int lineNumber) {
    string search_target1 = " " + _functionName + "(";
    string search_target2 = " " + _functionName + " ";
    bool flag = false;
    for (int i =0 ; i < _content.size(); i++){
        if ((i+1) == lineNumber){
            continue;
        }
        else if ((_content[i].find(search_target1) < _content[i].size() || _content[i].find(search_target2) < _content[i].size()) && _content[i].find("function") >= _content[i].size()){
            flag = true;
            break;
        }
        else
            continue;
    }
    return flag;
}

vector<string> publicToExternal::replacePublic(vector<string> _content, vector<int> _rowNumber) {
    vector<string> new_content;
    for (int i = 0; i<_content.size(); i++){
        if(count(_rowNumber.begin(), _rowNumber.end(), i+1)){
            //contains public
            int index = _content[i].find(" public ");
            int index1 = _content[i].find(" public{");
            int pos = max(index, index1);
            //cout<<_content[i].replace(pos, string(" public").size(), " external")<<endl;
            new_content.push_back(_content[i].replace(pos, string(" public").size(), " external") + "\n");
        }
        else{
            new_content.push_back(_content[i] + "\n");
            continue;
        }
    }
    return new_content;
}
