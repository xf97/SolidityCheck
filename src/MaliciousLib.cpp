//
// Created by xiaofeng on 2019/11/29.
//

//This program is used to detect whether the program depends on external
//libraries or not.

//source file

/*
author=__xiaofeng__
*/

//using head files
#include <iostream>
#include "MaliciousLib.h"

//constructor
MaliciousLib::MaliciousLib(const string _report_name, const vector<string> _content) {
    report_name = _report_name;
    content = _content;
    MLName = "Malicious libraries.";
    OtherOperation = "Third-party libraries can be malicious. Avoid external dependencies or ensure that third-party code implements only the intended functionality. Calling library functions will be executed by external calls. Be sure to check the return value of library functions.\nVulnerability level:";
    flag = false;
}

//destructor
MaliciousLib::~MaliciousLib() {
    report_name.clear();
    content.clear();
    MLName.clear();
    OtherOperation.clear();
    row_number.clear();
}

//get detect report
string MaliciousLib::MakeReport(const vector<int>& _row_number) {
    if (_row_number.empty()) {
        return "No malicious libraries.\n\n";
    }
    string _report = "";
    _report += "[Vulnerability 11]\n";
    _report += "vulnerability name: ";
    _report += MLName;
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
    if (flag == false)
        OtherOperation += "warning";
    else
        OtherOperation += "error";
    if (OtherOperation.size() != 0) {
        _report += "additional description: ";
        _report += OtherOperation;
        _report += '\n';
    }
    return _report;
}

//execute detection
void MaliciousLib::Detection() {
    for (int i = 0; i < content.size(); i++) {
        if (IsLib(content[i])) {
            row_number.push_back((i + 1));
            //Strip out the library name
            GetLibName(content[i]);
        }
    }
    //Finding library function calls
    for (int i = 0; i < content.size(); i++) {
        if (IsLibCall(content[i])) {
            if (IsIf(content[i]) || IsRequire(content[i]))
                continue;
            else {
                row_number.push_back((i + 1));
                flag = true;
            }
        }
    }
}

void MaliciousLib::Re_Detection()
{
    regex reg_lib{ ML_RE_LIB };
    for (int i = 0; i < content.size(); i++) {
        if (content[i].find("library")<content[i].size()) {
            smatch s;
            if (regex_match(content[i], s, reg_lib)) {
                row_number.push_back(i + 1);
                GetLibName(content[i]);
            }
        }
    }
    //Finding library function calls
    for (int i = 0; i < content.size(); i++) {
        if (IsLibCall(content[i])) {
            regex reg1{ ML_RE_IF };
            smatch s;
            if (regex_match(content[i],s,reg1))
                continue;
            else {
                row_number.push_back((i + 1));
                flag = true;
            }
        }
    }
}

//if _str  is "including a library" ,return true
//else return false
bool MaliciousLib::IsLib(const string& _str) {
    if (_str.find(ML_LIB) < _str.size())
        return true;
    else
        return false;
}

//this function is used to get library's name,
//and add this name into LibNames
void MaliciousLib::GetLibName(const string& _str) {
    //get "library" index
    int index = _str.find(ML_LIB);
    index += 8;
    string lib_name = "";
    while (_str[index] == ' ')
        index++;
    while (isalnum(_str[index]) || (_str[index] == '_')) {
        lib_name += _str[index];
        index++;
    }
    LibNames.push_back(lib_name);
}

//If the statement is an if statement, return true
//else return false
bool MaliciousLib::IsIf(const string& _str) {
    if (_str.find(ML_IF1) < _str.size() || _str.find(ML_IF2) < _str.size())
        return true;
    return false;
}


//If the statement is an require statement, return true
//else return false
bool MaliciousLib::IsRequire(const string& _str) {
    if (_str.find(ML_REQUIRE1) < _str.size() || _str.find(ML_REQUIRE2) < _str.size())
        return true;
    return false;
}


//return row_number size()
int MaliciousLib::GetNumber() {
    return row_number.size();
}

//return row_number
vector<int> MaliciousLib::GetRowNumber() {
    return row_number;
}

//If the statement contains library function calls, return true
//else return false
bool MaliciousLib::IsLibCall(const string& _str) {
    string temp = "";
    for (int i = 0; i < LibNames.size(); i++) {
        temp = LibNames[i];
        temp.push_back('.');
        if (_str.find(temp) < _str.size()) {
            temp.pop_back();
            temp += ML_RE_FUN_SUFFIX;
            regex reg{ temp };
            smatch s;
            if (regex_search(_str, s, reg))
                return true;
            else
                return false;
        }
        temp.clear();
    }
    return false;
}

void MaliciousLib::OutLibName() {
    for (auto i = LibNames.begin(); i != LibNames.end(); i++)
        cout << (*i) << endl;
}
