//This part of the program is used to detect the use of byte[]

//source file

/*
author=__xiaofeng__
*/

#include "ByteArray.h"

ByteArray::ByteArray(const string _report_name, const vector<string>& _content)
{
	report_name = _report_name;
	content = _content;
	BAName = "Byte Array";
	OtherOperation = "Using byte[] instead of bytes will result in more gas consumption.\nVulnerability level:warning";
}

ByteArray::~ByteArray() {
	report_name.clear();
	content.clear();
	BAName.clear();
	OtherOperation.clear();
	row_number.clear();
}

string ByteArray::MakeReport(const vector<int>& _row_number) {
	if (_row_number.empty()) {
		return "No byte[].\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 15]\n";
	_report += "vulnerability name: ";
	_report += BAName;
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

int ByteArray::GetNumber() {
	return row_number.size();
}

vector<int> ByteArray::GetRowNumber() {
	return row_number;
}

void ByteArray::Detection()
{
	for (int i = 0; i < content.size(); i++) {
		if (IsByte(content[i])) {
			row_number.push_back((i + 1));
		}
	}
}

void ByteArray::Re_Detection()
{
	regex reg{BA_RE_BYTE};
	for (int i = 0; i < content.size(); i++) {
		if (content[i].find("byte") < content[i].size()) {
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

bool ByteArray::IsByte(const string& _str) {
	string temp = "";
	for (char c : _str) {
		if (!isblank(c))
			temp.push_back(c);
	}
	if (temp.find(BA_BYTE) < temp.size())
		return true;
	return false;
}
