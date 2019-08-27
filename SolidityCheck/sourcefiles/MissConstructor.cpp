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
	//掠过"contract"关键字
	left += 8;
	//再次掠过空格
	while (left < _str.size() && isblank(_str[left]))
		left++;
	//开始截取合约名
	right = left;
	while (right < _str.size() && (isalnum(_str[right]) || _str[right] == '_') && _str[right]!= '{')
		right++;
	//返回合约名
	return _str.substr(left, right-left);
}

MissConstru::MissConstru(const string _report_name, const vector<string> _content)
{
	report_name = _report_name;
	content = _content;
	MCName = "Miss Constructor";
	OtherOperation = "Missing constructors may cause contract safety problems. Please add a constructor, or check the spelling of the function names of existing constructors.";
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
		return "No Miss constructor.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 23]\n";
	_report += "vulnerability name: ";
	_report += MCName;
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
				cout << "匹配开始. " << j<<" "<<contractName << endl;
				regex reg2{ MC_RE_Constructor };
				while (mc.DoMatch(content[j]) == false) {
					//Detection constructor
					j++;
				}
				cout << "匹配结束. " << j << endl;
				i = j;
			}
			else
				i++;
		}
		else
			i++;
	}
}
