//The program is used to detect balance equality
//for example:
/*
	if(this.balance == 42 ether){
		//todo
		}
*/
//an adversary can forcibly send ether to any account by mining or via selfdestruct.

//head file

/*
author=_xiaofeng_
*/

#ifndef _BALANCEEQUALITY_H_
#define _BALANCEEQUALITY_H_

//using head files
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <regex>

//using namespace 
using namespace std;

//const constants
const static string BE_LEAK1 = "this.balance==";
const static string BE_LEAK2 = "==this.balance";
const static string BE_IF1 = " if(";
const static string BE_IF2 = " if ";
const static string BE_WHILE1 = " while(";
const static string BE_WHILE2 = " while ";
const static string BE_FOR1 = " for(";
const static string BE_FOR2 = " for ";
const static string BE_REQUIRE1 = " require(";
const static string BE_REQUIRE2 = " require ";

//the regex define of Balance equality
const static string BE_RE_IF_WHILE_REQUIRE = "^(\\s)*((if)|(require)|(while))(\\s)*(\\()(.)*(((this.balance)(\\s)*(==)(\\s)*(\\d)+(\\s)*(ether))|((\\d)+(\\s)*(ether)(\\s)*(==)(\\s)*(this.balance)))(.)*(\\))(.)*$";
const static string BE_RE_FOR = "^(\\s)*(for)(\\s)*(\\()(.)*(;)(.)*(((this.balance)(\\s)*(==)(\\s)*(\\d)+(\\s)*(ether))|((\\d)+(\\s)*(ether)(\\s)*(==)(\\s)*(this.balance)))(.)*(;)(.)*(\\))(.)*$";

class Balance {
private:
	//data
	vector<string> content;	//be detected contract's content;
	string report_name;		//report file name
	vector<int> row_number;	//code lines that may have vulnerabilities
	string BEName;
	string OtherOperation;
protected:
	bool IfStatement(const string& _str);
	bool WhileStatement(const string& _str);
	bool ForStatement(const string& _str);
	bool RequireStatement(const string& _str);
	string FilterBlank(const string& _str);
	bool Leak(const string& _str);
public:
	//constructor
	Balance(const string _report_name, const vector<string> _content);
	//destructor
	~Balance();
	//splicing report string
	string MakeReport(const vector<int>& _row_number);
	//execute detection
	void Detection();
	//regex detection
	void Re_Detection();
	//return row_number size
	int GetNumber();
	//return row_number
	vector<int> GetRowNumber();
};



#endif
