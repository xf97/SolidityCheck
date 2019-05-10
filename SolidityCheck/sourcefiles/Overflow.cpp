//This part of the program is used to detect statements that may cause integer overflow, 
//and to deal with possible overflow errors by inserting statements.

//source file

/*
author=__xiaofeng__
*/


#include "Overflow.h"
#include <iostream>
#include <iomanip>


string Overflow::RewriteCon(const string  _str, const vector<string>& _ope)
{
	string temp = "\tuint256 anti_overflow_temp = "+_ope[0]+";\n";
	if (_str.find("-=") < _str.size() || _str.find("*=") < _str.size()) {
		temp += _str;
		return temp;
	}
	else {
		cout << "wrong statement.\n";
		return "error.\n";
	}
}

string Overflow::GetLeft(const string & _str)
{
	int index = 0;
	if (_str.find("+=") < _str.size()) {
		index = _str.find("+=");
	}
	else if (_str.find("-=") < _str.size()) {
		index = _str.find("-=");
	}
	else if (_str.find("*=") < _str.size()) {
		index = _str.find("*=");
	}
	else if (_str.find("/=") < _str.size()) {
		index = _str.find("/=");
	}
	else {
		index = _str.find("%=");
	}
	index--;
	while (isblank(_str[index]))
		index--;
	string left = "";
	while (isalnum(_str[index]) || (_str[index] == '_') || (_str[index] == '(') || (_str[index] == ')') || _str[index]=='[' || _str[index]==']' || _str[index]=='.') {
		left.push_back(_str[index]);
		index--;
	}
	reverse(left.begin(), left.end());
	return left;
}

string Overflow::GetRight(const string & _str)
{
	int index = 0;
	if (_str.find("+=") < _str.size()) {
		index = _str.find("+=");
	}
	else if (_str.find("-=") < _str.size()) {
		index = _str.find("-=");
	}
	else if (_str.find("*=") < _str.size()) {
		index = _str.find("*=");
	}
	else if (_str.find("/=") < _str.size()) {
		index = _str.find("/=");
	}
	else {
		index = _str.find("%=");
	}
	index+=2;
	while (isblank(_str[index]))
		index++;
	string right = "";
	while (isalnum(_str[index]) || (_str[index] == '_') || (_str[index] == '(') || (_str[index] == ')') || _str[index] == '[' || _str[index] == ']' || _str[index] == '.') {
		right.push_back(_str[index]);
		index++;
	}
	return right;
}

string Overflow::RewriteSta(const string & _str)
{
	string left = GetLeft(_str);
	string right = GetRight(_str);
	int type = GetNewType(_str);
	if (type != -1) {
		switch (type)
		{
		case 1:
			return left + "=" + right + "+" + left + ";";
		case 2:
			return left + "=" + left + "-" + right + ";";
		case 3:
			return left + "=" + right + "*" + left + ";";
		case 4:
			return left + "=" + left + "/" + right + ";";
		case 5:
			return left + "=" + left + "%" + right + ";";
		default:
			return "";
		}
	}
	return "";
}

string Overflow::ProcessBar(const int _rate)
{
	int star = 20 * _rate/100;
	int line = 20 - star;
	string bar = "[";
	while (star > 0) {
		bar.push_back('*');
		star--;
	}
	bar += "->";
	while (line > 0) {
		bar.push_back('.');
		line--;
	}
	bar += ']';
	return bar;
}

bool Overflow::IsOperation(const string & _str)
{
	if (_str.find('+') > _str.size() && _str.find('-') > _str.size() && _str.find('*') > _str.size() && _str.find('/') > _str.size() && _str.find('%') > _str.size())
		return false;
	regex reg{OF_RE_OPERATION};
	smatch s;
	if (regex_match(_str, s, reg)) {
		return true;
	}
	return false;
}


bool Overflow::IsSafeMath(const string & _str)
{
	string temp = "";
	for (char c : _str)
		temp.push_back(tolower(c));
	if ((_str.find(OF_LIBRARY) < _str.size() || _str.find(OF_CONTRACT) < _str.size()) && (temp.find(" safemath ") < temp.size() || temp.find(" safemath{") < temp.size()))
		return true;
	return false;
}

int Overflow::GetStartIndex(const int i)
{
	int j = i + 1;
	while (!IsCIL(content[j]))
		j++;
	return j;
}

bool Overflow::IsCIL(const string & _str)
{
	if (_str.find(OF_CONTRACT) < _str.size() || _str.find(OF_INTERFACE) < _str.size() || _str.find(OF_LIBRARY) < _str.size())
		return true;
	return false;
}

void Overflow::OutVec(const vector<string>& _vec)
{
	string filename = report_name.substr(0, report_name.size() - 14);
	filename += OF_NO_OVERFLOW;
	ofstream outFile(filename.c_str());
	if (!outFile.is_open()) {
		cout << "Pile insertion contract failure.\n";
		return;
	}
	for (auto i = _vec.begin(); i != _vec.end(); i++)
		outFile << (*i) << endl;
	outFile.close();
	cout << "Pile insertion contracts to prevent integer overflow have been generated.\n";
	cout << "File name: " << filename << endl;
	return;
}

vector<string> Overflow::GetOpe(const string & _str)
{
	vector<string> results;
	string temp = "";
	int equIndex = _str.find('=');
	equIndex--;
	while (isblank(_str[equIndex]))
		equIndex--;
	while (isalnum(_str[equIndex]) || _str[equIndex] == '_' || _str[equIndex] == '[' || _str[equIndex] == ']' || _str[equIndex] == '(' || _str[equIndex] == ')' || _str[equIndex] == '.') {
		temp.push_back(_str[equIndex]);
		equIndex--;
		if (equIndex < 0)
			break;
	}
	reverse(temp.begin(), temp.end());
	results.push_back(temp);
	temp.clear();
	equIndex = _str.find('=');
	equIndex++;
	while (isblank(_str[equIndex]))
		equIndex++;
	while (isalnum(_str[equIndex]) || _str[equIndex] == '_' || _str[equIndex] == '[' || _str[equIndex] == ']' || _str[equIndex] == '(' || _str[equIndex] == ')' || _str[equIndex] == '.') {
		temp.push_back(_str[equIndex]);
		equIndex++;
	}
	results.push_back(temp);
	temp.clear();
	while (isblank(_str[equIndex]) || (_str[equIndex]=='+') || (_str[equIndex]=='-') || (_str[equIndex]=='/') || (_str[equIndex]=='*') || (_str[equIndex]=='%'))
		equIndex++;
	while (isalnum(_str[equIndex]) || _str[equIndex] == '_' || _str[equIndex] == '[' || _str[equIndex] == ']' || _str[equIndex] == '(' || _str[equIndex] == ')' || _str[equIndex] == '.') {
		temp.push_back(_str[equIndex]);
		equIndex++;
	}
	results.push_back(temp);
	temp.clear();
	return results;
}

string Overflow::GetCode(const string & _str, const vector<string>& _ope,bool _flag)
{
	if (_flag) {
		if (_str.find("*") < _str.size() && _str.find("=") < _str.size()) {
			return "\n require(" + _ope[1] + "==0 || " + _ope[0] + "/" + _ope[1] + "==anti_overflow_temp);\n";
		}
		else if (_str.find("-") < _str.size() && _str.find("=") < _str.size()) {
			return "\n require(anti_overflow_temp > " + _ope[2] + " );\n";
		}
	}
	int type = GetType(_str);
	if (type != -1) {
		switch (type)
		{
		case 1:
			return "\n require(" + _ope[0] + ">=" + _ope[1] + ");\n";
		case 2:
			return "\n require(" + _ope[2] + "<=" + _ope[1] + ");\n";
		case 3:
			return "\n require(" + _ope[1] + "==0 || " + _ope[0] + "/" + _ope[1] + "==" + _ope[2] + ");\n";
		case 4:
			return "\n require(" + _ope[2] + ">0);\n";
		case 5:
			return "\n require(" + _ope[2] + "!=0);\n";
		default:
			return "";
		}
	}
	else {
		cout<<"Input statement format error.\n";
		return "";
	}
}

int Overflow::GetType(const string & _str)
{
	if (_str.find('+') < _str.size())
		return 1;
	else if (_str.find('-') < _str.size())
		return 2;
	else if (_str.find('*') < _str.size())
		return 3;
	else if (_str.find('/') < _str.size())
		return 4;
	else if (_str.find('%') < _str.size())
		return 5;
	else
		return -1;
}

int Overflow::GetNewType(const string & _str)
{
	if (_str.find("+=") < _str.size())
		return 1;
	else if (_str.find("-=") < _str.size())
		return 2;
	else if (_str.find("*=") < _str.size())
		return 3;
	else if (_str.find("/=") < _str.size())
		return 4;
	else if (_str.find("%=") < _str.size())
		return 5;
	else
		return -1;
}

void Overflow::OutputPosition()
{
	ofstream outFile(OF_POSITION);
	if (!outFile.is_open()) {
		cout << "File creation failed of record insertion location!\n";
		return;
	}
	string filename = report_name.substr(0, report_name.size() - 14);
	filename += "_backup.txt";
	outFile << "Row Number Reference Document: " << filename << endl;
	for (auto i = row_number.begin(); i != row_number.end(); i++) {
		outFile << "Row Number: " << (*i)  << endl;
	}
	outFile.close();
	cout << "Insert location file write completed.\n";
}

bool Overflow::NewIsOperation(const string & _str)
{
	if (_str.find("+=") > _str.size() && _str.find("-=") > _str.size() && _str.find("*=") > _str.size() && _str.find("/=") > _str.size() && _str.find("%=") > _str.size())
		return false;
	regex reg{ OF_RE_NEW_OPERATION };
	smatch s;
	if (regex_match(_str, s, reg)) {
		return true;
	}
	return false;
}

Overflow::Overflow(const string _report_name, const vector<string> _content)
{
	report_name = _report_name;
	content = _content;
	OFName = "Integer overflow";
	OtherOperation = "Integer overflow can bring unexpected effects, which may cause capital losses and be used by malicious accounts. It is recommended to check the results of operations or use the SafeMath library for operations.\nVulnerability level:warning";
	InsertFlag = false;
}

Overflow::~Overflow() {
	report_name.clear();
	content.clear();
	OFName.clear();
	OtherOperation.clear();
	row_number.clear();
}

int Overflow::GetNumber() {
	return row_number.size();
}

vector<int> Overflow::GetRowNumber() {
	return row_number;
}

void Overflow::Detection()
{
	bool flag = false;
	cout << "-----Start detecting-----\n";
	for (int i = 0; i < content.size(); i++) {
		double rate = (double)(i + 1) / (content.size());
		cout << "\r" <<setiosflags(ios::fixed)<<setprecision(0)<<(rate*100)<<"%"<<ProcessBar(int(rate*100));
		//don't check safemath code
		if (IsSafeMath(content[i])) {
			int j = GetStartIndex(i);
			i = j;
		}
		else if (IsOperation(content[i])) {
			InsertFlag = true;
			row_number.push_back((i + 1));
			vector<string> opes = GetOpe(content[i]);
			string insertCode = GetCode(content[i], opes,flag);
			content[i] += insertCode;
		}
		else if (NewIsOperation(content[i])) {
			InsertFlag = true;
			row_number.push_back((i + 1));
			string temp = RewriteSta(content[i]);
			vector<string> opes = GetOpe(temp);
			if (content[i].find("-=") < content[i].size() || content[i].find("*=") < content[i].size()) {
				//special statement.rewrite content[i]
				content[i] = RewriteCon(content[i], opes);
				flag = true;
			}
			string insertCode = GetCode(temp, opes,flag);
			flag = false;
			content[i] += insertCode;
		}
		else
			continue;
	}
	cout << endl;
	if (InsertFlag == true) {
		OutVec(content);
		OutputPosition();
	}
	else
		cout << "No integer overflow.\n";
	cout << "-----End of detection-----\n";
	if (row_number.empty())
		return;
	else {
		cout << "-----Insert line number-----\n";
		for (auto i = row_number.begin(); i != row_number.end(); i++)
			cout << "line "<<(*i) << endl;
	}
}

string Overflow::MakeReport(const vector<int>& _row_number) {
	if (_row_number.empty()) {
		return "No integer overflow.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 23]\n";
	_report += "vulnerability name: ";
	_report += OFName;
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
