//The program is used to detect balance equality
//for example:
/*
	if(this.balance == 42 ether){
		//todo
		}
*/
//an adversary can forcibly send ether to any account by mining or via selfdestruct.

//source file

/*
author=_xiaofeng_
*/

//using head files
#include "BalanceEquality.h"
#include <iostream>

//constructor
Balance::Balance(const string _report_name, const vector<string> _content) {
	content = _content;
	report_name = _report_name;
	BEName = "Balance equality";
	OtherOperation = "Avoid strict comparisons of contract balances. An attacker can force a change in the balance of the contract either by selfdestruct or by mining to send the ether. \nVulnerability level:error ";
}

//destructor
Balance::~Balance() {
	content.clear();
	report_name.clear();
	BEName.clear();
	OtherOperation.clear();
	row_number.clear();
}

//get report
string Balance::MakeReport(const vector<int>& _row_number) {
	if (_row_number.size() == 0) {
		return "No balanace equality.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 3]\n";
	_report += "vulnerability name: ";
	_report += BEName;
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

//Balance::Detection,execute detection
void Balance::Detection() {
	for (int i = 0; i < content.size(); i++) {
		if (IfStatement(content[i])) {
			string temp = FilterBlank(content[i]);
			if (Leak(temp)) {
				row_number.push_back((i + 1));
			}
		}
		if (WhileStatement(content[i])) {
			string temp = FilterBlank(content[i]);
			if (Leak(temp)) {
				row_number.push_back((i + 1));
			}
		}
		if (ForStatement(content[i])) {
			string temp = FilterBlank(content[i]);
			if (Leak(temp)) {
				row_number.push_back((i + 1));
			}
		}
		if (RequireStatement(content[i])) {
			string temp = FilterBlank(content[i]);
			if (Leak(temp)) {
				row_number.push_back((i + 1));
			}
		}
		else
			continue;
	}
}

void Balance::Re_Detection()
{
	regex reg_if{ BE_RE_IF_WHILE_REQUIRE };
	regex reg_for{ BE_RE_FOR };
	for (int i = 0; i < content.size(); i++) {
		if (content[i].find("this.balance") < content[i].size()) {
			smatch s;
			if (regex_match(content[i], s, reg_if) || regex_match(content[i], s, reg_for))
				row_number.push_back((i + 1));
			else
				continue;
		}
		else
			continue;
	}
}

//if _str is if-statement ,return true
bool Balance::IfStatement(const string& _str) {
	if ((_str.find(BE_IF1) < _str.size()) || (_str.find(BE_IF2) < _str.size()))
		return true;
	return false;
}

//if _str is while-statement ,return true
bool Balance::WhileStatement(const string& _str) {
	if ((_str.find(BE_WHILE1) < _str.size()) || (_str.find(BE_WHILE2) < _str.size()))
		return true;
	return false;
}


//if _str is for-statement ,return true
bool Balance::ForStatement(const string& _str) {
	if ((_str.find(BE_FOR1) < _str.size()) || (_str.find(BE_FOR2) < _str.size()))
		return true;
	return false;
}

//if _str is require-statement ,return true
bool Balance::RequireStatement(const string& _str) {
	if ((_str.find(BE_REQUIRE1) < _str.size()) || (_str.find(BE_REQUIRE2) < _str.size()))
		return true;
	return false;
}

//Filter blank/space in _str
string Balance::FilterBlank(const string& _str) {
	string temp = "";
	for (int i = 0; i < _str.size(); i++) {
		if (_str[i] == ' ' || _str[i] == '\t')
			continue;
		else
			temp += _str[i];
	}
	return temp;
}

//if _str contains BE_LEAK1 or BE_LEAK2,return true
//else false
bool Balance::Leak(const string& _str) {
	if ((_str.find(BE_LEAK1) < _str.size()) || (_str.find(BE_LEAK2) < _str.size()))
		return true;
	return false;
}

//return number of vulnerabilities
int Balance::GetNumber() {
	return row_number.size();
}

//return row_number
vector<int> Balance::GetRowNumber() {
	return row_number;
}