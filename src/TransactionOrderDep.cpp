//
// Created by xiaofeng on 2020/6/8.
//

#include "TransactionOrderDep.h"
#include <iostream>

//source file

TransactionOrderDep::TransactionOrderDep(const string _report_name, const vector<string> _content) {
    report_name = _report_name;
    content = _content;
    TODName = "Transaction order dependence";
    OtherOperation = "Miners can decide which transactions are packaged into the blocks and the\n"
                     "order in which transactions are packaged. The current main impact of this\n"
                     "kind of bugs is the approve function in the ERC20 token standard.\nBug level: warning";
}

TransactionOrderDep::~TransactionOrderDep() {
    report_name.clear();
    content.clear();
    TODName.clear();
    OtherOperation.clear();
    row_number.clear();
}

int TransactionOrderDep::GetNumber() {
    return row_number.size();
}

vector<int> TransactionOrderDep::GetRowNumber() {
    return row_number;
}

string TransactionOrderDep::MakeReport(const vector<int> &_row_number) {
    if (_row_number.empty()) {
        return "No transaction order dependence.\n\n";
    }
    string _report = "";
    _report += "[Bug 23]\n";
    _report += "bug name: ";
    _report += TODName;
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

void TransactionOrderDep::Re_Detection() {
    regex reg{TOD_RE_APPROVE};
    for (int i = 0; i < content.size(); i++){
        if (content[i].find(TOD_APPROVE) < content[i].size()){
            smatch s;
            if (regex_search(content[i], s, reg)){
                row_number.push_back((i+1));
            }
        }
    }
}
