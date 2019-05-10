//Using addr.call.value(x)() to transmit Ethernet coins will send all gas,
//which may introduce security risks.

//source file

/*
author=__xiaofeng__
*/


#include "AllGas.h"
#include <iostream>

bool AllGas::IsCallValue(const string & _str)
{
	if (_str.find(AG_VALUE) < _str.size() && _str.find(AG_BRACKETS) < _str.size())
		return true;
	return false;
}

bool AllGas::IsGas(const string & _str)
{
	if (_str.find(AG_GAS) < _str.size())
		return true;
	return false;
}

void AllGas::NoBlank(const string & _str, string & _temp)
{
	_temp.clear();
	for (char c : _str) {
		if (!isblank(c))
			_temp.push_back(c);
	}
}

AllGas::AllGas(const string _report_name, const vector<string> _content)
{
	report_name = _report_name;
	content = _content;
	AGName = "Transfer forwards all gas.";
	OtherOperation = "Using addr.call.value(x)() to transmit Ethernet coins will send all gas,which may introduce security risks.\nVulnerability level:warning";
}

AllGas::~AllGas()
{
	report_name.clear();
	content.clear();
	AGName.clear();
	OtherOperation.clear();
	row_number.clear();
}

string AllGas::MakeReport(const vector<int>& _row_number)
{
	if (_row_number.empty()) {
		return "No transfer forwards all gas.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 20]\n";
	_report += "vulnerability name: ";
	_report += AGName;
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

int AllGas::GetNumber() {
	return row_number.size();
}

vector<int> AllGas::GetRowNumber() {
	return row_number;
}

void AllGas::Detection()
{
	string temp = "";
	for (int i = 0; i < content.size(); i++) {
		NoBlank(content[i], temp);
		if (IsCallValue(temp)) {
			if (IsGas(temp))
				continue;
			else
				row_number.push_back((i + 1));
		}
	}
}

void AllGas::Re_Detection()
{
	regex reg{ AG_RE_ALLGAS };
	regex reg1{ AG_RE_NOGAS };
	for (int i = 0; i < content.size(); i++) {
		if (content[i].find(".call")<content[i].size() && content[i].find(".value")<content[i].size()) {
			smatch s;
			if (regex_search(content[i], s, reg) && !regex_search(content[i],s,reg1))
				row_number.push_back(i + 1);
			else
				continue;
		}
		else
			continue;
	}
}




