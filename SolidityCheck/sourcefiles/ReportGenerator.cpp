//Detection Report Generator

//source file

/*
author=__xiaofeng__
*/

//using head files
#include <iostream>
#include "ReportGenerator.h"


//constructor
Output::Output(const string _file_name, const string _report_name, const int _code_rows) {
	report_name = _report_name;
	numbers = 0;
	file_name = _file_name;
	code_rows = _code_rows;
}

//destructor
Output::~Output() {
	report_name.clear();
	report_content.clear();
}

//Output::AddString,add string into report_content
void Output::AddString(const string _str) {
	report_content.push_back(_str);
}

//AddNumber,add number of vulnerabilities into numbers
void Output::AddNumber(const int _num) {
	numbers += _num;
}

//output vector<string> to a file
void Output::OutReport(Time& t) {
	ofstream outFile(report_name.c_str());
	if (!OutError(outFile)) {
		cout << "Failed to generate test report. Please check the test contract file.\n";
		return;
	}
	outFile << "file name: " << file_name << endl;
	outFile << "number of lines of code: " << code_rows << endl;
	outFile << "use time: " << t.timeConsuming_ds() << " s." << endl;
	outFile << "total number of vulnerabilities: " << numbers << endl;
	outFile << "\n";
	auto i = report_content.begin();
	for (; i != report_content.end(); i++)
		outFile << (*i) << endl;
	if (i == report_content.end())
		cout << "Detection report has generated.\n";
	else
		cout << "Detection report generation failed, please try again.\n";
	return;
}


//read-in error handing
bool Output::InError(const ifstream& in) {
	if (!in.is_open())
		return false;
	return true;
}

//output error handing
bool Output::OutError(const ofstream& out) {
	if (!out.is_open())
		return false;
	return true;
}

