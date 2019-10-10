//The program detects the use of tx.origin for authentication  

/*
author=_xiaofeng_
*/

//source file

//using head files
#include <iostream>
#include "TxOrigin.h"

//constructor
TxOrigin::TxOrigin(const string _report_name, const vector<string> _content) {
	report_name = _report_name;
	content = _content;
	TOName = "Using tx.origin for authentication";
	OtherOperation = "TX. origin is always an external account, and using tx.origin to authenticate may be invalid.\nVulnerability level:error";
}

//destructor
TxOrigin::~TxOrigin() {
	report_name.clear();
	content.clear();
	TOName.clear();
	OtherOperation.clear();
	row_number.clear();
}

//make detect report
string TxOrigin::MakeReport(const vector<int>& _row_number) {
	if (_row_number.empty()) {
		return "No tx.origin for authentication .\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 5]\n";
	_report += "vulnerability name: ";
	_report += TOName;
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
void TxOrigin::Detection() {
	for (int i = 0; i < content.size(); i++) {
		if (IsTo(content[i])) {
			if (IsIf(content[i])) {
				row_number.push_back((i + 1));
			}
			else if (IsRequire(content[i])) {
				row_number.push_back((i + 1));
			}
			else {
				continue;
			}
		}
	}
}

void TxOrigin::Re_Detection()
{
	regex reg{ TO_RE_TX };
	for (int i = 0; i < content.size(); i++) {
		if (content[i].find("tx.origin") < content[i].size()) {
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

//if the _str contains tx.origin,return true;
//else return false.
bool TxOrigin::IsTo(const string& _str) {
	if (_str.find(TO_TX) < _str.size())
		return true;
	return false;
}

//if the _str is if-statement,return true;
//else return false.
bool TxOrigin::IsIf(const string& _str) {
	if (_str.find(TO_IF1) < _str.size() || _str.find(TO_IF2) < _str.size())
		return true;
	return false;
}

//if the _str is reuqire-statement,return true;
//else return false.
bool TxOrigin::IsRequire(const string& _str) {
	if (_str.find(TO_REQUIRE1) < _str.size() || _str.find(TO_REQUIRE2) < _str.size())
		return true;
	return false;
}

//return number of vulnerabilities
int TxOrigin::GetNumber() {
	return row_number.size();
}

//return row_number
vector<int> TxOrigin::GetRowNumber() {
	return row_number;
}