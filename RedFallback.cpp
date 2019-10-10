//The 0.4.0 version of solidity language will automatically supplement 
//fallback function for contracts. The fallback functions provided by 
//contract writers may bring security risks.

//source file

/*
author=__xiaofeng__
*/

#include <iostream>
#include "RedFallback.h"

bool RedFallback::IsVersion(const string & _str)
{
	string temp = "";
	for (char c : _str) {
		if (!isblank(c))
			temp.push_back(c);
	}
	if (temp.find(RF_PRAGMA) < temp.size())
		return true;
	return false;
}

int RedFallback::GetVersion(const string & _str)
{
	vector<string> vec;
	split(_str, vec);
	istringstream iss(vec[1].c_str());
	int result;
	iss >> result;
	return result;
}

void RedFallback::split(const string & _str, vector<string>& vec, const char flag)
{
		vec.clear();
		istringstream iss(_str);
		string temp = "";

		while (getline(iss, temp, flag))
			vec.push_back(temp);
		temp.clear();
}

bool RedFallback::IsFallback(const string & _str)
{
	string temp = "";
	for (char c : _str) {
		if (!isblank(c))
			temp.push_back(c);
	}
	if (temp.find(RF_FALLBACK) < temp.size())
		return true;
	return false;
}

RedFallback::RedFallback(const string _report_name, const vector<string> _content)
{
	report_name = _report_name;
	content = _content;
	RFName = "Redundant refusal of payment";
	OtherOperation = "The 0.4.0 version of solidity language will automatically supplement fallback function for contracts. The fallback functions provided by contract writers may bring security risks.\nVulnerability level:error";
	VersionNum = 5;
}

RedFallback::~RedFallback() {
	report_name.clear();
	content.clear();
	RFName.clear();
	OtherOperation.clear();
	row_number.clear();
}

string RedFallback::MakeReport(const vector<int>& _row_number) {
	if (_row_number.empty()) {
		return "No redundant refusal of payment.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 16]\n";
	_report += "vulnerability name: ";
	_report += RFName;
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

int RedFallback::GetNumber() {
	return row_number.size();
}

vector<int> RedFallback::GetRowNumber() {
	return row_number;
}

void RedFallback::Detection()
{
	for (auto i = content.begin(); i != content.end(); i++) {
		if (IsVersion(*i)) {
			VersionNum = GetVersion(*i);
			break;
		}
	}
	if (VersionNum >= RF_LIMIT) {
		for (int i = 0; i < content.size(); i++) {
			if (IsFallback(content[i])) {
				row_number.push_back((i + 1));
			}
		}
	}
	else
		return;
}

void RedFallback::SetVerion(const int _v)
{
	VersionNum = _v;
}

int RedFallback::GetVersion()
{
	return VersionNum;
	return 0;
}

void RedFallback::Re_Detection()
{
	for (auto i = content.begin(); i != content.end(); i++) {
		if ((*i).find("pragma ")<(*i).size() && (*i).find("solidity ")<(*i).size()) {
			regex reg{ RF_RE_VERSION };
			smatch s;
			if (regex_search(*i, s, reg)) {
				VersionNum = GetVersion(*i);
				break;
			}
			else
				continue;
		}
		else
			continue;
	}
	if (VersionNum >= RF_LIMIT) {
		for (int i = 0; i < content.size() -1 ; i++) {
			if (content[i].find("function")<content[i].size()) {
				//regex reg{ RF_RE_FALLBACK };
				regex reg{"(\\b)(function)(\\s)*(\\()(\\s)*(\\))(.)*(\\s)+(payable)(\\s)*" };
				regex reg1{ RF_RE_THROW };
				smatch s;
				smatch s1;
				if (regex_search(content[i], s, reg) && regex_search(content[i+1], s1,reg1)) {
					row_number.push_back((i + 1));
				}
				else
					continue;
			}
			else
				continue;
		}
	}
	else
		return;
}
