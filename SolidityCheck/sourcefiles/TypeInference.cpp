//Unsafe type inference. Using type inference can lead to erroneous 
//consequences (such as infinite loops).

//source file

/*
author=__xiaofeng__
*/

//using head files
#include <iostream>
#include "TypeInference.h"

//constructor
TypeInfer::TypeInfer(const string _report_name, const vector<string> _content) {
	report_name = _report_name;
	content = _content;
	TIName = "Unsafe type inference";
	OtherOperation = "Unsafe type inference. Using type inference can lead to erroneous consequences (such as infinite loops).\nVulnerability level:error";
}

//destructor
TypeInfer::~TypeInfer() {
	report_name.clear();
	content.clear();
	TIName.clear();
	OtherOperation.clear();
	row_number.clear();
}

//get detect report
string TypeInfer::MakeReport(const vector<int>& _row_number) {
	if (_row_number.empty()) {
		return "No unsafe type inference.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 6]\n";
	_report += "vulnerability name: ";
	_report += TIName;
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
void TypeInfer::Detection() {
	for (int i = 0; i < content.size(); i++) {
		if (IsVar(content[i])) {
			if (IsFor(content[i])) {
				vector<string> temp;
				split(content[i], temp);
				if (IsVar(temp[0])) {
					string right = SplitRight(temp[0]);
					if (IsNum(right)) {
						if (Leak(right)) {
							row_number.push_back((i + 1));
						}
					}
					else {
						continue;
					}
				}
				else
					continue;
			}
			else {
				string right = SplitRight(content[i]);
				if (IsNum(right)) {
					if (Leak(right)) {
						row_number.push_back((i + 1));
					}
				}
				else {
					continue;
				}
			}
		}
	}

}

//if _str contains "var",return true
//else return false
bool TypeInfer::IsVar(const string& _str) {
	if (_str.find(TI_VAR1) < _str.size() || _str.find(TI_VAR2) < _str.size())
		return true;
	return false;
}

//if _str is for-statement,return true
//else return false
bool TypeInfer::IsFor(const string& _str) {
	if ((_str.find(TI_FOR1) < _str.size() || _str.find(TI_FOR2) < _str.size()) && (_str.find(TI_USING) >= _str.size()))
		return true;
	return false;
}

//get the string to the right of the operator
string TypeInfer::SplitRight(const string& _str) {
	string temp = "";
	int i = _str.find('=');
	i++;
	while (isblank(_str[i]))
		i++;
	while (isdigit(_str[i])) {
			temp += _str[i];
			i++;
	}
	//reverse(temp.begin(), temp.end());
	return temp;
}

//if _str is number,return true
//else return false
bool TypeInfer::IsNum(const string& _str) {
	for (auto i = _str.begin(); i != _str.end(); i++) {
		if (!isdigit(*i))
			return false;
	}
	return true;
}

//Returns true if the integer does not make the identifier type 
//the type with the largest representation range
bool TypeInfer::Leak(const string& _str) {
	double num = Transform(_str);
	if ((num > TI_MAX) || (num < TI_MIN))
		return false;
	return true;
}

//C++ split
void TypeInfer::split(const string& _str, vector<string>& vec, const char flag) {
	vec.clear();
	istringstream iss(_str);
	string temp = "";

	while (getline(iss, temp, flag))
		vec.push_back(temp);
	temp.clear();
}

//string to double
double TypeInfer::Transform(const string& _right) {
	istringstream is(_right);
	double temp;
	is >> temp;
	return temp;
}

//return number of vulnerabilities
int TypeInfer::GetNumber() {
	return row_number.size();
}

//return row_number
vector<int> TypeInfer::GetRowNumber() {
	return row_number;
}

void TypeInfer::Re_Detection()
{
	regex reg{TI_RE_VAR};
	for (int i = 0; i < content.size(); i++) {
		if (content[i].find("var") < content[i].size()) {
			smatch s;
			string::const_iterator start = content[i].begin();
			string::const_iterator end = content[i].end();
			while (regex_search(start,end, s, reg)) {
				string right = SplitRight(s[0]);
				if (Leak(right))
					row_number.push_back(i + 1);
				start = s[0].second;
			}
		}
		else
			continue;
	}
}
