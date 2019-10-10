//This part of the program is used to detect the use
//of random numbers in smart contracts(excluding the use of off-chain services)

//source file

/*
author=_xiaofeng_
*/

//using head file
#include "Random.h"
#include <iostream>

//constructor
Random::Random(const string _report_name, const vector<string> _content) {
	report_name = _report_name;
	content = _content;
	RAName = "Using unsafe random numbers.";
	OtherOperation = "Ethereum is distributed. It is impossible to obtain the same random number in each distributed node in order to reach consensus. The miners always get the random number which is beneficial to them. If you want to use the random number in the block chain, you can get the safe random number through the out-of-chain service. \nVulnerability level:error";
}

//destructor
Random::~Random() {
	report_name.clear();
	content.clear();
	RAName.clear();
	OtherOperation.clear();
	row_number.clear();
}

//get detect report
string Random::MakeReport(const vector<int>& _row_number) {
	if (_row_number.empty()) {
		return "No unsafe random numbers.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 9]\n";
	_report += "vulnerability name: ";
	_report += RAName;
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
void Random::Detection(RA_Match& rma) {
	vector<int> index;
	vector<string> arguments;
	for (int i = 0; i < content.size(); i++) {
		if (IsHash(content[i], index)) {
			//encryption function is the core
			arguments.clear();
			arguments = rma.DoMatch(content[i], index);
			if (IsRandom(arguments)) {
				row_number.push_back((i + 1));
			}
		}
	}
}

void Random::Re_Detection()
{
	regex reg{ RA_RE_RANDOM };
	for (int i = 0; i < content.size(); i++) {
		if (content[i].find(RA_KECCAK) < content[i].size() || content[i].find(RA_SHA256) < content[i].size()|| content[i].find(RA_SHA3) < content[i].size() || content[i].find(RA_RIPEMD) < content[i].size()) {
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

//if _str contains encryption function,return true;
//else return false
bool Random::IsHash(const string& _str, vector<int>& _index) {
	_index.clear();
	string temp = "";
	for (int i = 0; i < _str.size(); i++) {
		if (isalnum(_str[i]) || _str[i] == '_')
			temp += _str[i];
		else {
			if (temp == RA_KECCAK || temp == RA_SHA256 || temp == RA_SHA3 || temp == RA_RIPEMD) {
				_index.push_back(i);
			}
			temp = "";
		}
	}
	if (_index.empty())
		return false;
	else
		return true;
}

//if _str contains now,block.timestamp,block.difficultym,blockhash,return true
//else return false
bool Random::IsRandom(const vector<string>& _argu) {
	for (auto i = _argu.begin(); i != _argu.end(); i++) {
		if ((*i).find(RA_BLOCK) < (*i).size() || (*i).find(RA_NOW) < (*i).size())
			return true;
	}
	return false;
}


//RA_Match constructor
RA_Match::RA_Match() {
	count = 0;
}

//RA_Match destructor
RA_Match::~RA_Match() {
	count = 0;
	brackets.clear();
}

//RA_Match::Reset,reset count=0 and clear the brackets
void RA_Match::Reset() {
	count = 0;
	brackets.clear();
}

//RA_Match::IsMatching,if match return true;else return false
bool RA_Match::IsMatching() {
	if (brackets.empty() && count != 0)
		return true;
	return false;
}

//RA_Match::DoMatch
vector<string> RA_Match::DoMatch(const string& _str, const vector<int>& _index) {
	vector<string> temp;
	string str = "";
	for (auto i = _index.begin(); i != _index.end(); i++) {
		int j = (*i);
		while (!IsMatching()) {
			if (_str[j] == '(') {
				count++;
				brackets.push_back('(');
			}
			else if (_str[j] == ')') {
				brackets.pop_back();
			}
			else {
				str += _str[j];
			}
			j++;
		}
		temp.push_back(str);
		str.clear();
		Reset();
	}
	return temp;
}

//return number of vulnerabilities
int Random::GetNumber() {
	return row_number.size();
}

//return row_number
vector<int> Random::GetRowNumber() {
	return row_number;
}