//Detection Report Generator

//head file

/*
author=__xiaofeng__
*/

#ifndef _REPORTGENERATOR_H_
#define _REPORTGENERATOR_H_

//using head files
#include <string>
#include <vector>
#include <fstream>
#include <iterator>
#include <ctime>

//using namespace 
using namespace std;

//class timer
class Time {
private:
	clock_t start;	//start time
	clock_t end;	//end time
public:
	Time() {
		start = end = 0;
	}
	void startTime() {
		start = clock();
	}
	void endTime() {
		end = clock();
	}
	int timeConsuming_s() {
		return (end - start) / CLOCKS_PER_SEC;
	}
	double timeConsuming_ds() {
		return (double(end - start)) / CLOCKS_PER_SEC;
	}
	clock_t timeCounsuming_clocks() {
		return end - start;
	}
};



//class output
class Output {
private:
	string file_name;
	string report_name;
	vector<string> report_content;
	int code_rows;
	int numbers;
protected:
	//Read-in error handing
	bool InError(const ifstream& in);
	//output error handing
	bool OutError(const ofstream& out);
public:
	//constructor
	Output(const string _file_name, const string _report_name, const int _code_rows);
	//destructor
	~Output();
	//make file
	void OutReport(Time& t);
	//add string into content
	void AddString(const string _str);
	//add numbers
	void AddNumber(const int _num);
};

#endif
