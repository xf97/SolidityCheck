//send instead of transfer.It is recommended to use transfer instead of send to 
//send Ethernet currency, so that when an exception occurs to send, the program can 
//be terminated. 

//source file

/*
author=__xiaofeng__
*/

//using head files
#include <iostream>
#include "Send.h"

//constructor
Send::Send(const string _report_name, const vector<string> _content) {
	report_name = _report_name;
	content = _content;
	SEName = "Send instead of transfer.";
	OtherOperation = "It is recommended to use transfer instead of send to send Ethernet currency, so that when an exception occurs to send, the program can be terminated.\nVulnerability level:warning";
}

//destructor
Send::~Send() {
	report_name.clear();
	content.clear();
	SEName.clear();
	OtherOperation.clear();
	row_number.clear();
}

//get detect report
string Send::MakeReport(const vector<int>& _row_number) {
	if (_row_number.empty()) {
		return "No send instead of transfer.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 8]\n";
	_report += "vulnerability name: ";
	_report += SEName;
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

//execute detection
void Send::Detection() {
	for (int i = 0; i < content.size(); i++) {
		if (IsSend(content[i])) {
			row_number.push_back((i + 1));
		}
	}

}

void Send::Re_Detection()
{
	regex reg{ SE_RE_SEND };
	for (int i = 0; i < content.size(); i++) {
		if (content[i].find(".send ")<content[i].size() || content[i].find(".send(")<content[i].size()) {
			smatch s;
			if (regex_search(content[i], s, reg))
				row_number.push_back(i + 1);
			else
				continue;
		}
		else
			continue;
	}

}

//if _str contains keyword "send",return true
//else return false
bool Send::IsSend(const string& _str) {
	if (_str.find(SE_SEND1) < _str.size() || _str.find(SE_SEND2) < _str.size())
		return true;
	return false;
}

//return number of vulnerabilities
int Send::GetNumber() {
	return row_number.size();
}

//return row_number
vector<int> Send::GetRowNumber() {
	return row_number;
}