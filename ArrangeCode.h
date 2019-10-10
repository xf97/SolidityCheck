//This program is used to arrange the 
//source code in order to better analyze.

//head file

/*
author=__xiaofeng__
*/

#ifndef _ARRANGECODE_H_
#define _ARRANGECODE_H_

//using headfiles
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <regex>

//using namespace
using namespace std;

//const constants 
const static string FORMATSUFFIX = "_format.sol";
const static string CON = " contract ";
const static string INT = " interface ";
const static string LIB = " library ";
const static string FUN = " function ";
const static string MOD = " modifier ";
const static string EVE = " event ";
const static string IF1 = " if ";
const static string IF2 = " if(";
const static string FOR1 = " for(";
const static string FOR2 = " for ";
const static string WHILE1 = " while(";
const static string WHILE2 = " while ";
const static string REPORTSUFFIX = "_detect.report";

//for regex
const static string AR_RE_FOR = "(\\s)*(for)(\\s)*(\\()";

//independent output for vector<string>
ostream & operator<<(ostream& os, const vector<string>& vec);

//file I/O class
class FileIO {
private:
	//private data
	vector<string> vec_content;	//row by row
	string str_content;	//char by char
	string filename;	//filename
protected:
	//Read-in error handing
	bool InError(const ifstream& in);
	//output error handing
	bool OutError(const ofstream& out);
public:
	//constructor
	FileIO(const string& _filename);
	//no argument constructor
	FileIO();
	//return file nane
	string outFileName();
	//get the content of the file to vector and string
	void ReadIn();
	//output the vector
	vector<string> OutVector();
	//output the string
	string OutString();
	//print vector<string>
	void PrintVec();
	//output string to a file
	void OutToFile(const string& filename, const string& new_content);
	//return code_rows
	int GetRows();
	//destructor
	~FileIO();
};

//code formatting
//arrangement objectives:
//1.all declaration/definition statements are contained in one line (including'{')--done 
//2.the last'}'line of contract / library / interface body is alone--done
//3.the if/while/for statements contains the left'{'completed in one line--done
//4.the rest of the statements are completed in one line--done
//5.delete all comments--done
//6.delete all empty lines--done

//input:origin content and origin file name
//output: formatting source code file
//arrangecode class
class ArrangeCode {
private:
	//data
	string old_content;	//origin string and tempoary variable
	string new_content;	//formatting string
	string old_name;	//origin name
	string new_name;	//formatting file name
	vector<string> vec_content;	//vector<string> content
	string detect_result;	//file name of test report  
protected:
	//function 
	bool IsFor(const string& _str);
	vector<string> F_Blank(vector<string>& _content);
	void GetReportName(const string& _old_name);
	bool IsBlankLine(const string& _str);
	void GetNewName(const string& _old_name);
	void FilterSingle(const string& _old_str, string& _new_str);
	void FilterMul(const string& _old_str, string& _new_str);
	void ArrangeConDef(const string& type, string& _old_str);
	void ArrangeFunDef(const string& type, string& _old_str);
	void ArrangeLoopDef(const string& type, string& _old_str);
	void FilterBlankLine();
	void Seprate(string& _old_str);
	vector<int> GetConIndex(const string& _old_str);
	void ArrangeRemain(const string& _old_str, string& _new_str);
	void split(const string& _str, vector<string>& vec, const char flag = ' ');
	void StripSpace(string& _str);
	void Strip(vector<string>& vec);
	string JustOneLine(const string& _old_str);
	vector<string> SpecialFor(vector<string>& vec);
	void NoMiddleN(string& _str);
	bool IsForIndex(const vector<int>& _index, const int i);
public:
	//constructor
	ArrangeCode(const string _old_content, const string _old_name);
	//return old_name
	string OutOldName();
	//return detect report file name
	string OutReport();
	//return new_name
	string OutNewName();
	//perform formatting operations 
	void FormatCode();
	//string to vector<string>
	void StrToVec(const string& content);
	//vector<string> to string
	string VecToStr(const vector<string>& _vec);
	//output new content
	string OutString();
	//output old content
	string OutOldString();
	//output vec_content
	vector<string> OutVec();
	//destructor
	~ArrangeCode();
};
#endif
