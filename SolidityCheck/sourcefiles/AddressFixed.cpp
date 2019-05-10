//Address type with fixed value
//It is dangerous to assign value to address variables using constants. 
//Please check carefully whether the account that the address points to 
//is a contract/library.Note that the contract/library may self-destruct.

//source file

/*
author=__xiaofeng__
*/

//using head files
#include <iostream>
#include "AddressFixed.h"

//constructor
Address::Address(const string _report_name, const vector<string> _content) {
	report_name = _report_name;
	content = _content;
	AFName = "Address type with fixed value";
	OtherOperation = "It is dangerous to assign value to address variables using constants. Please check carefully whether the account that the address points to is a contract/library. Note that the contract/library may self-destruct.\nVulnerability level:error";
}

//destructor
Address::~Address() {
	report_name.clear();
	content.clear();
	row_number.clear();
	AFName.clear();
	OtherOperation.clear();
}

//get detect report
string Address::MakeReport(const vector<int>& _row_number) {
	if (_row_number.empty()) {
		return "No address type with fixed value.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 12]\n";
	_report += "vulnerability name: ";
	_report += AFName;
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

//return row_number.size()
int Address::GetNumber() {
	return row_number.size();
}

//return row_number
vector<int> Address::GetRowNumber() {
	return row_number;
}

//execute Detection
void Address::Detection() {
	int temp_index;
	string temp_name;
	for (int i = 0; i < content.size(); i++) {
		if (IsConst(content[i])) {
			GetAddressName(temp_name, content[i]);
			if (IsAddress(content[i])) {
				row_number.push_back((i + 1));
			}
			else {
				//Forward Looking for Identifier
				string _str;
				temp_index = i;
				while (temp_index >= 0) {
					if (IsAddress(content[temp_index]) && content[temp_index].find(temp_name) < content[temp_index].size()) {
						GetIdent(content[temp_index], _str);
						if (temp_name == _str) {
							row_number.push_back((i + 1));
							break;
						}
						else
							temp_index--;
					}
					else {
						temp_index--;
					}				
				}
			}
		}
	}
}

void Address::Re_Detection()
{
	int temp_index;
	string temp_name;
	for (int i = 0; i < content.size(); i++) {
		if (RE_IsConst(content[i])) {
			GetAddressName(temp_name, content[i]);
			if (IsAddress(content[i])) {
				row_number.push_back((i + 1));
			}
			else {
				string AF_RE_DECLA = "^(\\s)*(address)(\\s)*((\\[)(.)*(\\]))?(\\s)+(.)*(\\b)(";
				AF_RE_DECLA += temp_name;
				AF_RE_DECLA += ")";
				AF_RE_DECLA += "(\\b)";
				int temp = i;
				regex reg{ AF_RE_DECLA };
				while (temp >= 0) {
					if (content[temp].find("address") < content[temp].size()) {
						smatch s;
						if (regex_search(content[temp], s, reg)) {
							row_number.push_back(i + 1);
							break;
						}
						else
							temp--;
					}
					else
						temp--;
				}
			}
		}
		else
			continue;
	}
}

//If the statement contains a hexadecimal constant up to 40 bits, 
//return true;else return false
bool Address::IsConst(const string& _str) {
	int count = 0;
	int i;
	if (_str.find(AF_0X) >= _str.size())
		return false;
	if (_str.find(AF_EQ) >= _str.size())
		return false;
	i = _str.find(AF_EQ);
	i += 1;
	while (isblank(_str[i]))
		i++;
	if (_str[i] == '0' && (_str[i + 1] == 'x' || _str[i + 1] == 'X')) {
		i += 2;
		while (isalnum(_str[i])) {
			i++;
			count++;
		}
		if (count == 40)
			return true;
		else
			return false;
	}
	else
		return false;
}

void Address::GetAddressName(string & _name, const string & _str)
{
	_name.clear();
	int i = _str.find(AF_EQ);
	i--;
	while (isblank(_str[i]))
		i--;
	while (isalnum(_str[i]) || (_str[i] == '_') || (_str[i])=='[' || (_str[i]==']')) {
		_name.push_back(_str[i]);
		i--;
	}
	reverse(_name.begin(), _name.end());
	if (_name.find('[') < _name.size() && _name.find(']') < _name.size()) {
		int index = _name.find('[');
		_name = _name.substr(0, index);
	}
}

bool Address::IsName(const string& _name,const string & _str)
{
	if (IsAddress(_str) && IsEqual(_str))
		return true;
	return false;
}

bool Address::IsAddress(const string & _str)
{
	int i = 0;
	while (isblank(_str[i]))
		i++;
	string temp_str = _str.substr(i, _str.size() - i);
	if (temp_str.find(AF_ADDRESS1)==0)
		return true;
	return false;
}

bool Address::IsEqual(const string & _str)
{
	int count = 0;
	int index = 0;
	while (_str.find(AF_EQ,index) < _str.size()) {
		index = _str.find(AF_EQ, index);
		count++;
	}
	if (count == 1)
		return true;
	else
		return false;
}

void Address::GetIdent(string  _str,string& _name)
{
	_str.push_back(' ');
	_name.clear();
	bool flag = false;
	if (_str.find(" public ") < _str.size() || _str.find(" external ") < _str.size() || _str.find(" private ") < _str.size() || _str.find(" internal ") < _str.size())
		flag = true;
	vector<string> vec;
	string temp = "";
	for (char c : _str) {
		if (isblank(c)) {
			if (temp.empty())
				continue;
			else {
				if (temp.find(';') < temp.size())
					temp = temp.substr(0, temp.size() - 1);
				vec.push_back(temp);
				temp.clear();
			}
		}
		else {
			temp.push_back(c);
		}
	}
	if (vec.size() < 2)
		return;
	if (flag == true)
		_name = vec[2];
	else
		_name = vec[1];
}

void Address::split(const string& _str, vector<string>& vec, const char flag) {
	vec.clear();
	istringstream iss(_str);
	string temp = "";

	while (getline(iss, temp, flag))
		vec.push_back(temp);
	temp.clear();
}

bool Address::RE_IsConst(const string & _str)
{
	if (_str.find("0x") > _str.size() && _str.find("0X") > _str.size())
		return false;
	regex reg{ AF_RE_ADDRESS };
	smatch s;
	if (regex_search(_str, s, reg))
		return true;
	return false;
}
