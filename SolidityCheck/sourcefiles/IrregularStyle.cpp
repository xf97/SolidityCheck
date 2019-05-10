//Solidity specifies how functions, events are named, and arrays
//are declared. Compliance with specifications improves code readability

//source file

/*
author=__xiaofeng__
*/


#include "IrregularStyle.h"
#include <iostream>

bool IrregularStyle::IsFun(const string & _str)
{
	if (_str.find(IS_FUNCTION2) < _str.size())
		return true;
	return false;
}

bool IrregularStyle::IsEvent(const string & _str)
{
	if (_str.find(IS_EVENT2) < _str.size())
		return true;
	return false;
}

bool IrregularStyle::IsArray(const string & _str)
{
	if ((_str.find(IS_LEFT) < _str.size()) && (_str.find(IS_RIGHT) < _str.size())) {
		string temp = "";
		for (char c : _str) {
			if (!isblank(c))
				temp.push_back(c);
		}
		int lindex = temp.find(IS_LEFT);
		int rindex = temp.find(IS_RIGHT);
		if (lindex > rindex)
			return false;
		bool flag1 = true;
		bool flag2 = true;
		for (int i = lindex+1; i < rindex; i++) {
			if (!isdigit(temp[i])) {
				flag1 = false;
				break;
			}
		}
		for (int i = lindex + 1; i < rindex; i++) {
			if (!(isalnum(temp[i]) || temp[i] == '_')) {
				flag2 = false;
				break;
			}
		}
		if (flag1 == true || flag2 == true)
			return true;
		else
			return false;
	}
	return false;
}

void IrregularStyle::GetFunName(const string & _str,string& _name)
{
	_name.clear();
	string temp = "";
	for (char c : _str) {
		if (!isblank(c))
			temp.push_back(c);
	}
	int index = temp.find(IS_FUNCTION1);
	index += 8;
	while (temp[index] != '(') {
		_name.push_back(temp[index]);
		index++;
	}
	if (_name.empty()) {
		_name = "fallback";
	}
}

void IrregularStyle::GetEventName(const string & _str, string & _name)
{
	_name.clear();
	string temp = "";
	for (char c : _str) {
		if (!isblank(c))
			temp.push_back(c);
	}
	int index = temp.find(IS_EVENT1);
	index += 5;
	while (temp[index] != '(') {
		_name.push_back(temp[index]);
		index++;
	}
}

bool IrregularStyle::Good(const string & _str)
{
	int lindex = _str.find(IS_LEFT);
	if (isblank(_str[lindex - 1]))
		return false;
	else
		return true;
}

IrregularStyle::IrregularStyle(const string _report_name, const vector<string> _content)
{
	report_name = _report_name;
	content = _content;
	ISName = "Irregular style.";
	OtherOperation = "Solidity specifies how functions, events are named, and arrays are declared. Compliance with specifications improves code readability.\nVulnerability level:warning";
}

IrregularStyle::~IrregularStyle()
{
	report_name.clear();
	content.clear();
	ISName.clear();
	OtherOperation.clear();
	row_number.clear();
}

string IrregularStyle::MakeReport(const vector<int>& _row_number) {
	if (_row_number.empty()) {
		return "No irregular style.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 17]\n";
	_report += "vulnerability name: ";
	_report += ISName;
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

int IrregularStyle::GetNumber() {
	return row_number.size();
}

vector<int> IrregularStyle::GetRowNumber() {
	return row_number;
}

void IrregularStyle::Detection()
{
	string name = "";
	for (int i = 0; i < content.size(); i++) {
		if (IsFun(content[i])) {
			GetFunName(content[i], name);
			if (islower(name[0]))
				continue;
			else
				row_number.push_back((i + 1));
		}
		else if (IsEvent(content[i])) {
			GetEventName(content[i], name);
			if (isupper(name[0]))
				continue;
			else
				row_number.push_back((i + 1));
		}
		else if (IsArray(content[i])) {
			if (Good(content[i]))
				continue;
			else
				row_number.push_back((i + 1));
		}
		else
			continue;
	}
}

void IrregularStyle::Re_Detection()
{
	for (int i = 0; i < content.size(); i++) {
		if (content[i].find("function")<content[i].size()) {
			regex reg1{ IS_RE_FUNCTION };
			smatch s1;
			if (regex_search(content[i], s1, reg1))
				row_number.push_back(i + 1);
			else
				continue;
		}
		else if (content[i].find("event")<content[i].size()) {
			regex reg2{ IS_RE_EVENT };
			smatch s2;
			if (regex_search(content[i], s2, reg2))
				row_number.push_back(i + 1);
			else
				continue;
		}
		else if (content[i].find('[')<content[i].size() && content[i].find(']')<content[i].size()) {
			regex reg3{ IS_RE_ARRAY };
			smatch s3;
			if (regex_search(content[i], s3, reg3))
				row_number.push_back(i + 1);
			else
				continue;
		}
		else
			continue;
	}
}


