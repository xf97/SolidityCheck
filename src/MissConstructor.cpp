//
// Created by xiaofeng on 2019/11/29.
//

//This part of the program is used to detect missing constructor errors,
//which include not adding constructors, or constructor name spelling errors.

//source file

/*
author = __xiaofeng__
*/

//The procedure for detecting missing constructors is as follows:
//step 1:Find each contract head
//step 2:Use bracket matching to determine the scope of the contract body and
//		 retrieve statements in the contract body
//step 3:If there are two types of sentence below, it is considered that there
//		 is no such error, otherwise there is.
//statement 1: function ContractName(__pargs__) {
//statement 2: constructor(__pargs__) {


//using head files
#include "MissConstructor.h"
#include <iostream>


//MC_Match's constructor
MC_Match::MC_Match() {
    count = 0;
}

//MC_Match's destructor
MC_Match::~MC_Match() {
    brackets.clear();
    count = 0;
}

//Brackets matching
bool MC_Match::DoMatch(const string& _statement) {
    //Useless sentence
    if (_statement.find("{") >= _statement.size() && _statement.find("}") >= _statement.size())
        return false;
    for (char c : _statement) {
        if (c == '{') {
            brackets.push_back('{');
            count++;
        }
        else if (c == '}') {
            brackets.pop_back();
        }
    }
    if (brackets.empty() && count != 0) {
        return true;
    }
    else
        return false;
}

string MissConstru::getConName(const string & _str)
{
    int right;
    int left = _str.find("contract");
    left += 8;
    while (left < _str.size() && isblank(_str[left]))
        left++;
    right = left;
    while (right < _str.size() && (isalnum(_str[right]) || _str[right] == '_') && _str[right]!= '{')
        right++;
    return _str.substr(left, right-left);
}

vector<int> MissConstru::getRowNumber()
{
    return row_number;
}

int MissConstru::GetNumber()
{
    return row_number.size();
}

MissConstru::MissConstru(const string _report_name, const vector<string> _content)
{
    report_name = _report_name;
    content = _content;
    MCName = "Incorrect constructor name";
    OtherOperation = "Constructors are special functions that are called only once during the contract creation.\n"
                     "They often perform critical, privileged actions such as setting the owner of the contract.\n "
                     "Before Solidity version 0.4.22, the only way of defining a constructor was to create a function\n "
                     "with the same name as the contract class containing it. A function meant to become a constructor\n"
                     "becomes a normal, callable function if its name doesn't exactly match the contract name. This\n"
                     "behavior sometimes leads to security issues, in particular when smart contract code is re-used\n"
                     "with a different name but the name of the constructor function is not changed accordingly.\nBug level:error";
}

MissConstru::~MissConstru()
{
    content.clear();
    report_name.clear();
    row_number.clear();
    MCName.clear();
    OtherOperation.clear();
}

string MissConstru::MakeReport(const vector<int>& _row_number)
{
    if (_row_number.empty()) {
        return "No missing constructor.\n\n";
    }
    string _report = "";
    _report += "[Bug 18]\n";
    _report += "bug name: ";
    _report += MCName;
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

void MissConstru::Re_Detection()
{
    //regex
    regex reg1{ MC_RE_HeadOfContract };
    //detection
    for (int i = 0; i < content.size();) {
        if (content[i].find("contract") < content[i].size()) {
            smatch s;
            if (regex_match(content[i], s, reg1)) {
                //find head of contract
                //Take out the name of the contract
                string contractName = getConName(content[i]);
                //start matching brackets
                MC_Match mc;
                int j = i;
                regex reg2{ MC_RE_Constructor };
                string MC_RE_FunctionContract = "^(\\s)*(function)(\\s)*(" + contractName + ")(\\s)*(\\()";
                regex reg3{ MC_RE_FunctionContract };
                bool flag = false;
                while (mc.DoMatch(content[j]) == false) {
                    smatch s1, s2;
                    //Detection constructor
                    if (content[j].find("constructor") < content[j].size() || content[j].find("function") < content[j].size()) {
                        if (regex_search(content[j], s1, reg2) || regex_search(content[j], s2, reg3)) {
                            //Find the constructor
                            flag = true;
                            break;
                        }
                        else {
                            j++;
                        }
                    }
                    else
                        j++;
                }
                if (flag == false) {
                    row_number.push_back((i + 1));
                }
                i = j;
            }
            else
                i++;
        }
        else
            i++;
    }
}
