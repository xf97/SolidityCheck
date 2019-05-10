//This program is used to detect costly loop

//source file

/*
author=_xiaofeng_
*/

//Costly loop by detecting the for or while condition in the presence of any one of the following:
//1.a large integer with a default value of 68227, which is adjustable 
//2.variable identifier 
//3.function call 

//using head files
#include "CostlyLoop.h"
#include <iostream>

//Match::constructor
Match::Match() {
	count = 0;
}

//Match::destructor
Match::~Match() {
	brackets.clear();
	count = 0;
}

//Match::Reset,reset count=0 and clear the brackets
void Match::Reset() {
	count = 0;
	brackets.clear();
}

//Match::IsMatching,if match return true;else return false
bool Match::IsMatching() {
	if (brackets.size() == 0 && count != 0)
		return true;
	return false;
}

//Match::Match,execute matching
int Match::DoMatch(const vector<string>& _content, const int _row_number) {
	int temp = _row_number;
	if (_content[temp].find('{') >= _content[temp].size())
		return 1;
	while (!IsMatching()) {
		for (int i = 0; i < _content[temp].size(); i++) {
			if (_content[temp][i] == '{') {
				count++;
				brackets.push_back('{');
			}
			else if (_content[temp][i] == '}') {
				brackets.pop_back();
			}
			else
				continue;
		}
		temp++;
	}
	if (OnlyRightBracket(_content[temp-1])) {
		return (temp - _row_number - 2);
	}
	else {
		return (temp - _row_number);
	}
}

//if _str has only one char'}',return true
//else return false
bool Match::OnlyRightBracket(const string& _str) {
	for (auto i = _str.begin(); i != _str.end(); i++) {
		if (!isblank(*i) && (*i) != '}' && (*i)!='\n')
			return false;
	}
	return true;
}

//constrcutor
CostlyLoop::CostlyLoop(const string _report_name, const vector<string> _content) {
	report_name = _report_name;
	content = _content;
	CLName = "Costly Loop";
	gas_limit = 10000;
	OtherOperation = "Miners limit the amount of gas that each transactions can spend. Transactions beyond that limit will not succeed. Please carefully detect the number of rows where the vulnerability is located and determine that the gas cost of the cycle is within a reasonable range. \nVulnerability level:warning ";
	gas_limit = 67668;
	OutGasLimit(67688);
}

//destructor
CostlyLoop::~CostlyLoop() {
	report_name.clear();
	content.clear();
	CLName.clear();
	OtherOperation.clear();
	row_number.clear();
}

//execute detection,Find the number of rows that may have vulnerabilities and add them to row_number(vector<int>)
void CostlyLoop::Detection(Match& ma) {
	vector<string> temp;
	for (int i = 0; i < content.size(); i++) {
		//1.find for/while statements
		if (IsFor(content[i])) {
			//2.separate conditional statements
			split(content[i], temp);
			//3.1 function call
			if (IsCall(temp[1])) {
				row_number.push_back((i + 1));
			}
			//3.2 member attribute
			else if (IsMember(temp[1])) {
				row_number.push_back((i + 1));
			}
			else {
				//3.3 constant or variable
				string right = SplitRight(temp[1]);
				//3.3.1 constant
				if (IsNum(right)) {
					int row = ma.DoMatch(content, i);
					if (Comparative(StrToInt(right), row)) {
						row_number.push_back((i + 1));
					}
					ma.Reset();
				}
				else {
					regex reg{ "(\\w)+" };
					smatch s;
					if (regex_match(right, s, reg))
						row_number.push_back((i + 1));
					else
						continue;
				}
			}
		}
		else if (IsWhile(content[i])) {
			//get conditional statement
			string condition = GetCondition(content[i]);
			//3.1 function call
			if (IsCall(condition)) {
				row_number.push_back((i + 1));
			}
			//3.2 member attribute
			else if (IsMember(condition)) {
				row_number.push_back((i + 1));
			}
			else {
				//3.3 constant or variable
				string right = SplitRight(condition);
				//3.3.1 constant
				if (IsNum(right)) {
					int row = ma.DoMatch(content, i);
					if (Comparative(StrToInt(right), row)) {
						row_number.push_back((i + 1));
					}
					ma.Reset();
				}
				else {
					regex reg{ "(\\w)+" };
					smatch s;
					if (regex_match(right, s, reg))
						row_number.push_back((i + 1));
					else
						continue;
				}
			}
		}
		else
			continue;
	}
}

//string to int
int CostlyLoop::StrToInt(const string& _str) {
	istringstream in(_str);
	int temp;
	in >> temp;
	return temp;
}

void CostlyLoop::OutGasLimit(const int _gas_limit)
{
	fstream file;
	file.open("GasLimit.ini",ios::in);
	if (!file) {
		file.close();
		ofstream outFile("GasLimit.ini");
		if (!outFile.is_open()) {
			cout << "Initialization Gas limit failed" << endl;
			outFile.close();
			return;
		}
		outFile << _gas_limit << endl;
		outFile.close();
		return;
	}
	else {
		return;
	}
}

//if _right*_row*PERGAS>gaslimit ,return true;else return false
bool CostlyLoop::Comparative(const int _right, const int _row) {
	if ((_right*_row*PERGAS) > GetGasLimit()) {
		return true;
	}
	return false;
}

//set new gas_limit
void CostlyLoop::SetGasLimit(const int _gas_limit) {
	gas_limit = _gas_limit;
}

//get present gas_limit
int CostlyLoop::GetGasLimit() {
	ifstream inFile("GasLimit.ini");

	if (!inFile.is_open()) {
		cout << "Getting gas limit failed.Use default value(67688).\n";
		return 67688;
	}
	int gasLimit;
	inFile >> gasLimit;
	inFile.close();
	return gasLimit;
}

//if _str is for statement,return true;else return false
bool CostlyLoop::IsFor(const string& _str) {
	/*
	regex reg{CL_RE_FOR};
	smatch s;
	if (regex_search(_str, s, reg)) {
		return true;
	}
	return false;*/
	regex reg{ CL_RE_NEWFOR };
	if (_str.find("for ") > _str.size() && _str.find("for(")>_str.size())
		return false;
	else {
		smatch s;
		if (regex_match(_str, s, reg)) {
			return true;
		}
		else
			return false;
	}
}

//if _str is while statement,return true;else return false
bool CostlyLoop::IsWhile(const string& _str) {
	if (_str.find(CL_WHILE1) > _str.size() && _str.find(CL_WHILE2) > _str.size())
		return false;
	else {
		regex reg{ CL_RE_NEWWHILE };
		smatch s;
		if (regex_match(_str, s, reg)) {
			return true;
		}
		else
			return false;
	}
}

//C++ split
void CostlyLoop::split(const string& _str, vector<string>& vec, const char flag) {
	vec.clear();
	istringstream iss(_str);
	string temp = "";

	while (getline(iss, temp, flag))
		vec.push_back(temp);
	temp.clear();
}

//determine whether this statement contains function calls
bool CostlyLoop::IsCall(const string& _str) {
	if (_str.find(CL_CALL1) > _str.size())
		return false;
	else {
		regex reg{ CL_RE_NEWCALL };
		smatch s;
		if (regex_search(_str, s, reg))
			return true;
		else
			return false;
	}
}

//determine whether this statement contains member attribute
bool CostlyLoop::IsMember(const string& _str) {
	if (_str.find(CL_CALL3) < _str.size())
		return true;
	return false;
}

//keep the string to the right of the operator
string CostlyLoop::SplitRight(const string& _str) {
	string temp = "";
	int i = _str.size() - 1;
	while (isalnum(_str[i]) || (_str[i]) == '_' || (_str[i] == ' ')) {
		if (_str[i] != ' ')
			temp += _str[i];
		i--;
	}
	reverse(temp.begin(), temp.end());
	return temp;
}

//determine whether a string can be converted to int
bool CostlyLoop::IsNum(const string& _str) {
	for (auto i = _str.begin(); i != _str.end(); i++) {
		if (!isdigit(*i))
			return false;
	}
	return true;
}

//keep the string to the left of the operator
string CostlyLoop::SplitLeft(const string& _str) {
	string temp = "";
	int i = 0;
	while (isalnum(_str[i]) || (_str[i] == ' ') || (_str[i] == '_')) {
		if (_str[i] != ' ')
			temp += _str[i];
		i++;
	}
	return temp;
}

//GetCondition,return "a" from "while(a)"
string CostlyLoop::GetCondition(const string& _str) {
	string temp = "";
	int count = 1;
	int index = _str.find('(');
	index++;
	while (count != 0) {
		if (_str[index] == '(') {
			temp.push_back(_str[index]);
			index++;
			count++;
		}
		else if (_str[index] == ')') {
			temp.push_back(_str[index]);
			index++;
			count--;
		}
		else {
			temp.push_back(_str[index]);
			index++;
		}
	}
	temp = temp.substr(0, temp.size() - 1);
	return temp;
}

//get report
string CostlyLoop::MakeReport(const vector<int>& _row_number) {
	if (_row_number.empty()) {
		return "No Costly Loop.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 2]\n";
	_report += "vulnerability name: ";
	_report += CLName;
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
	_report += "detect method: We detect the existence of function calls, member variables, and constants that can cause looping costs of 67668 gases in conditional statements for / while (the limit is adjustable).\n";
	return _report;
}

//return number of vulnerabilities
int CostlyLoop::GetNumber() {
	return row_number.size();
}

//return row_number
vector<int> CostlyLoop::GetRowNumber() {
	return row_number;
}

void CostlyLoop::Re_Detection()
{
	
}
