//In ERC20-compliant contracts, we do not recommend throwing exceptions in
//functions that return bool values, such as approve, transfer, transferFrom

//source file

/*
author=__xiaofeng__
*/

#include "ERC20Conflict.h"
#include <iostream>

bool ERC20::IsCI(const string & _str)
{
	if (_str.find("contract ") > _str.size() && _str.find("interface ") > _str.size())
		return false;
	else {
		regex reg{ EC_RE_ERC20 };
		smatch s;
		if (regex_search(_str, s, reg))
			return true;
		else
			return false;
	}
}

void ERC20::GetFunName(const string & _str, string & _name)
{
	_name.clear();
	string temp = "";
	for (char c : _str) {
		if (!isblank(c))
			temp.push_back(c);
	}
	int index = temp.find(EC_FUN2);
	index += 8;
	while (temp[index] != '(') {
		_name.push_back(temp[index]);
		index++;
	}
	if (_name.empty()) {
		_name = "fallback";
	}
}

bool ERC20::IsCon(const string & _str)
{
	if (_str.find("contract") < _str.size()) {
		regex reg{ "(\\b)(contract)(\\b)" };
		smatch s;
		if (regex_search(_str, s, reg))
			return true;
		else
			return false;
	}
	return false;
}

bool ERC20::IsInt(const string & _str)
{
	if (_str.find("interface") < _str.size()) {
		regex reg{ "(\\b)(interface)(\\b)" };
		smatch s;
		if (regex_search(_str, s, reg))
			return true;
		else
			return false;
	}
	return false;
}

void ERC20::GetName(const string  _str, string & _name)
{
	string temp = "";
	_name.clear();
	vector<string> vec;
	for (int i = 0; i < _str.size(); i++) {
		if (isblank(_str[i]))
			continue;
		else if (!isblank(_str[i]) && isblank(_str[i + 1])) {
			temp.push_back(_str[i]);
			vec.push_back(temp);
			temp.clear();
		}
		else if (!isblank(_str[i]) && !isblank(_str[i + 1])) {
			temp.push_back(_str[i]);
		}
	}
	for (auto i = vec.begin(); i != vec.end(); i++) {
		if ((*i) == "contract" || (*i) == "interface") {
			i++;
			_name = (*i);
			if ((*i).find('{') < (*i).size() || (*i).find(';')<(*i).size()) {
				_name = (*i).substr(0, (*i).size() - 1);
			}
			return;
		}
	}
	return;
}


bool ERC20::IsERC20(const string & _str)
{
	if (_str.find(EC_ERC20) < _str.size())
		return true;
	return false;
}

void ERC20::GetSons(vector<string>& _name)
{
	vector<string> name;
	MergeVec(_name, chain);
	vector<string> Name;
	for (int i = 0; i < content.size(); i++) {
		if (IsSonClass(content[i])) {
			GetFatherName(content[i], Name);
			if (InVec(_name, Name)) {
				name.push_back(GetSonName(content[i]));
			}
		}
	}
	if (name.empty()) {
		return;
	}
	else {
		GetSons(name);
		return;
	}
}

bool ERC20::IsSon(const vector<string>& _name, const string & _temp)
{
	for (auto i = _name.begin(); i != _name.end(); i++) {
		if ((*i) == _temp)
			return true;
	}
	return false;
}

bool ERC20::IsCIL(const string & _str)
{
	if (_str.find(EC_CON) < _str.size() || _str.find(EC_LIB) < _str.size() || _str.find(EC_INT) < _str.size())
		return true;
	return false;
}

bool ERC20::IsExcep(const string & _str)
{
	if (_str.find(EC_THROW1) < _str.size() || _str.find(EC_THROW2) < _str.size())
		return true;
	else if (_str.find(EC_ASSERT1) < _str.size() || _str.find(EC_ASSERT2) < _str.size())
		return true;
	else if (_str.find(EC_REVERT1) < _str.size() || _str.find(EC_REVERT2) < _str.size())
		return true;
	else if (_str.find(EC_REQUIRE1) < _str.size() || _str.find(EC_REQUIRE2) < _str.size())
		return true;
	else
		return false;
}

bool ERC20::IsSonClass(const string & _str)
{
	if (_str.find(EC_CON) < _str.size() && _str.find(EC_INHERIT) < _str.size())
		return true;
	return false;
}

void ERC20::GetFatherName(const string & _str, vector<string>& fname)
{
	string temp = "";
	for (char c : _str) {
		if (!isblank(c))
			temp.push_back(c);
	}
	int index = temp.find("is");
	index += 2;
	temp = temp.substr(index, temp.size() - index);
	if (temp.find('{') < temp.size())
		temp = temp.substr(0, temp.size() - 1);
	split(temp, fname);
	return;
}

void ERC20::OutVec(const vector<string>& _vec)
{
	for (auto i = _vec.begin(); i != _vec.end(); i++)
		cout << (*i) << endl;
}

bool ERC20::InVec(const vector<string>& _vec, const vector<string>& _name)
{
	for (auto i = _name.begin(); i != _name.end(); i++) {
		for (auto j = _vec.begin(); j != _vec.end(); j++) {
			if ((*i) == (*j))
				return true;
		}
	}
	return false;
}

void ERC20::MergeVec(const vector<string>& source, vector<string>& dest)
{
	for (auto i = source.begin(); i != source.end(); i++)
		dest.push_back(*i);
}

string ERC20::GetSonName(const string & _str)
{
	string _name = "",temp="";
	vector<string> vec;
	for (int i = 0; i < _str.size(); i++) {
		if (isblank(_str[i]))
			continue;
		else if (!isblank(_str[i]) && isblank(_str[i + 1])) {
			temp.push_back(_str[i]);
			vec.push_back(temp);
			temp.clear();
		}
		else if (!isblank(_str[i]) && !isblank(_str[i + 1])) {
			temp.push_back(_str[i]);
		}
	}
	for (auto i = vec.begin(); i != vec.end(); i++) {
		if ((*i) == "contract" || (*i) == "interface") {
			i++;
			_name = (*i);
			if ((*i).find('{') < (*i).size())
				_name = (*i).substr(0, (*i).size() - 1);
			return _name;
		}
	}
	return _name;
}

void ERC20::split(const string & _str, vector<string>& vec, const char flag)
{
	vec.clear();
	istringstream iss(_str);
	string temp = "";

	while (getline(iss, temp, flag))
		vec.push_back(temp);
	temp.clear();
}

bool ERC20::IsChain(const string & _str)
{
	string name = "";
	name = GetSonName(_str);
	if (IsSon(chain, name)) {
		return true;
	}
	return false;
}

bool ERC20::IsFun(const string & _str)
{
	if (_str.find(EC_FUN1) < _str.size()) {
		string name = "";
		GetFunName(_str, name);
		if (name == EC_APPROVE || name == EC_TRANSFER || name == EC_TRANSFROM)
			return true;
		return false;
	}
	else
		return false;
}

string ERC20::GetUpper(const string & temp)
{
	string _str = "";
	for (char c : temp) {
		if (islower(c))
			_str += toupper(c);
		else
			_str += c;
	}
	return _str;
}

ERC20::ERC20(const string _report_name, const vector<string> _content)
{
	report_name = _report_name;
	content = _content;
	ECName = "ERC20 API conflict.";
	OtherOperation = "In ERC20-compliant contracts, it does not recommend throwing exceptions in functions that return bool values, such as approve, transfer, transferFrom.\nVulnerability level:warning";
	ERC20Flag = false;
}

ERC20::~ERC20() {
	report_name.clear();
	content.clear();
	ECName.clear();
	OtherOperation.clear();
	row_number.clear();
}

string ERC20::MakeReport(const vector<int>& _row_number)
{
	if (_row_number.empty()) {
		return "No ERC20 api conflict.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 21]\n";
	_report += "vulnerability name: ";
	_report += ECName;
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

int ERC20::GetNumber()
{
	return row_number.size();
}

vector<int> ERC20::GetRowNumber() {
	return row_number;
}

void ERC20::Detection(EC_Match& ec) {
	string temp = "";
	for (auto i = content.begin(); i != content.end(); i++) {
		if (IsCI(*i)) {;
			GetName(*i, temp);
			temp = GetUpper(temp);
			if (IsERC20(temp)) {
				ERC20Flag = true;
				break;
			}
			else
				continue;
		}
	}
	if (ERC20Flag == false)
		return;
	else {
		vector<string> temp_name{ temp };
		GetSons(temp_name);
		for (int i = 0; i < content.size(); i++)
		{
			if (IsCon(content[i]) || IsInt(content[i])) {
				if (IsChain(content[i])) {
					for (int j = i + 1; j < content.size(); j++) {
						if (IsCIL(content[j])) {
							i = j-1;
							break;
						}
						else {
							if (IsFun(content[j]) && content[j].find('{') < content[j].size()) {
								int k = j;
								while (!ec.IsMatch()) {
									ec.Match(content[k]);
									if (IsExcep(content[k])) {
										row_number.push_back((k + 1));
										k++;
									}
									else {
										k++;
									}

								}
								ec.Reset();

							}
							else {
								continue;
							}
						}
					}
				}
				else
					continue;
			}
			else
				continue;
		}
	}
}

void ERC20::Re_Detection()
{
	regex reg{ EC_RE_ERC20 };
	for (auto i = content.begin(); i != content.end(); i++) {
		if ((*i).find("contract ") < (*i).size() || (*i).find("interface ") < (*i).size()) {
			smatch s;
			if (regex_search(*i, s, reg)) {

			}
			else
				continue;
		}
		else
			continue;
	}
}

void EC_Match::Match(const string & _str)
{
	for (char c : _str) {
		if (c == '{') {
			count++;
			brackets.push_back('{');
		}
		else if (c == '}') {
			brackets.pop_back();
		}
	}
}
