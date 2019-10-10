//This part of the program is used to detect self-destructive function statements
//There is no method to detect dangerous self-destructive functions based on source 
//code in the existing literature. The method we think of is still very elementary: 
//to detect the use of each self-destructive function, warning developers.

//source file

/*
author = __xiaofeng__
*/

//using head files
#include <iostream>
#include "Selfdestruct.h"

Selfdestruct::Selfdestruct(const string & _report_name, const vector<string>& _content)
{
	report_name = _report_name;
	content = _content;
	SDName = "Careful use of self-destructive functions";
	OtherOperation = "Use of self-destructive functions requires caution. Calls to self-destructive functions need to be authenticated. The address to which the ethers will be sent after the contract is self-destructed should not be controlled externally.\nVulnerability level:warning";
}

Selfdestruct::~Selfdestruct()
{
	row_number.clear();
	content.clear();
	SDName.clear();
	OtherOperation.clear();
	report_name.clear();
}

string Selfdestruct::MakeReport(const vector<int>& _row_number)
{
	if (_row_number.empty()) {
		return "No use of self-destructive functions.\n\n";
	}
	string _report = "";
	_report += "[Vulnerability 24]\n";
	_report += "vulnerability name: ";
	_report += SDName;
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

void Selfdestruct::Re_Detection()
{
	//regex
	regex reg1{ SD_RE_SELFDESTRUCT };
	regex reg2{ SD_RE_SUICIDE };
	//detect
	for (int i = 0; i < content.size(); i++) {
		//keywords filtering
		if (content[i].find("selfdestruct") < content[i].size() || content[i].find("suicide") < content[i].size()) {
			smatch s1;
			smatch s2;
			if (regex_search(content[i], s1, reg1) || regex_search(content[i], s2, reg2)) {
				//get the statement
				row_number.push_back((i + 1));
			}
			else
				continue;
		}
		else
			continue;
	}
}

vector<int> Selfdestruct::getRowNumber()
{
	return row_number;
}

int Selfdestruct::GetNumber()
{
	return row_number.size();
}


