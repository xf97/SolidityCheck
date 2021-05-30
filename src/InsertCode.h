//
// Created by xiaofeng on 2019/11/29.
//

//
// Created by xiaofeng on 2019/11/29.
//

//This part of the program is used to provide test contracts for detecting
//reentry vulnerabilities

//head files

/*
author=__xiaofeng__
*/

#ifndef _INSERTCODE_H_
#define _INSERTCODE_H_

//using head files
#include <string>
#include <iostream>
#include <vector>
#include <algorithm>
#include <iterator>
#include <utility>
#include <fstream>
#include <map>
#include <sstream>
#include <cstdlib>
#include <cctype>
#include <regex>

//using namespace
using namespace std;

//const constants
const string accountFlag = ".call.value";
const string mappingFlag1 = "mapping(address=>uint)";
const string mappingFlag2 = "mapping(address=>uint256)";
const string ReAexe = "	Aexe=0;\t //insert code";
const string ReBexe = "	Bexe=0;\t //insert code";
const string inheritKw = " is ";
const vector<string> init_seed = { ".call.value" };
const string CALLVALUE = ".call.value";
const string funcFlag = "function ";
const string contFlag = "contract ";
const string libFlag = "library ";
const string interFlag = "interface ";
const string appix1 = "_test.sol";
const string appix2 = "_chain.txt";
const string AEXE = "	uint256 public Aexe=0;\t //insert code";
const string BEXE = "	uint256 public Bexe=0;\t //insert code";
const string IC_CON = "contract";
const string IC_FUN = "function";
const string IC_LIB = "library";
const string IC_INT = "interface";
const string CONEND = "\n}\n";

//Data structures used
struct Node;
typedef Node* PNode;
struct Node {
    //����������Լ��
    string contName;
    //������
    string funcName;
    //Σ��/���ú�����������к�
    int rowNum;
    //ǰ������rowNum���Դ���������״�ṹ
    int preFunc;
    //̽���־��Ϊtrue��ʾ̽���
    bool flag;
    //�����ɼ���
    string limit;
};

ostream & operator<<(ostream& os, const vector<pair<int, string>>& in);
bool operator==(const Node& node1, const Node& node2);
ostream & operator<<(ostream& os, const Node& node);
ostream & operator<<(ostream & os, const vector<string>& arr);
ostream & operator<<(ostream & os, const vector<Node>& arr);
ostream & operator<<(ostream& os, const vector<vector<int>>& lo);
ostream & operator<<(ostream& os, const vector<int>& Lo);
ostream & operator<<(ostream & os, const map<string, vector<string>>& f);


//bracket matching recognition class
class IC_Match {
private:
    //data
    vector<char> brackets;
    int count;
protected:
    bool OnlyRightBracket(const string& _str);
public:
    //constructor
    IC_Match();
    //destructor
    ~IC_Match();
    //set new count;
    void Reset();
    //judging whether or not to match
    bool IsMatching();
    //execute matching
    bool DoMatch(const char c);
};

//class insert code
class InsertCode {
private:
    //data
    map<string, vector<string>> fathers;
    vector<Node> _chain;
    vector<string> contract;
    vector<Node> chainArr;
    vector<Node> chain;
    vector<vector<int>> location;
    vector<vector<string>> code;
    vector<string> FatherName;
    vector<string> content;
    vector<int> index;
    string filename;
protected:
    bool IsCallValue(const string& _str);
    void AdjustCode(vector<pair<int, string>>& code);
    string Re_GetConName(const string& _str);
    bool IsCIL(const string& _str);
    string getCode(const int row, const vector<pair<int, string>>& incode);
    bool inRowNum(const int row, const vector<pair<int, string>>& incode);
    vector<pair<int, string>> remDup(vector<pair<int, string>> in);
    vector<string> insertCode(const vector<string>& Content);
    vector<pair<int, string>> mergeArr(const vector<vector<int>>& Lo, const vector<vector<string>>& Co);
    vector<string> buildCode(const string& bal, const string& acc);
    string filterKeywords(const string& str);
    string getbalance(const string& str);
    string ignoreBlank(const string& str);
    string getBalance(const vector<string>& Content, const vector<int>& _lo);
    string getAccount(const vector<string>& Content, const vector<int>& _lo, const string& flag);
    vector<int> combineLocation(const int head, const int tail);
    int getTailRow(const Node& node);
    int strToInt(const string& str);
    Node isScalled(const Node& node, const vector<Node>& chain);
    int getHeadRow(const string& called, const int rownum, const vector<string>& Contract);
    void getContract(vector<string>& contract, const string& filename);
    void getNodes(vector<Node>& Chain, const string& filename);
    string getContName(const vector<string>& co);
    void deploy(const vector<string>& co);
    void outStrFile(const string& co, const string& filename);
    string makeDeploy(const string& str);
    string getLimit(const string& str);
    void outChain(const vector<Node>& Chain, const string& filename);
    string getTestConName(const string& str, const string& appix);
    bool isInChain(const vector<Node>& Chain, const Node& node);
    bool init();
    void merge(vector<Node>& chainArr, const vector<Node>& arr);
    vector<Node> re_search(const vector<string>& content, const Node& node);
    void getChain(const vector<string>& content, vector<Node>& arr);
    void file_err(const ofstream& outfile);
    void outToFile(const vector<string>& str, const string& filename);
    string splitContName(const string& str);
    bool str_in_seed(const string& str, const vector<string>& seed);
    void getContent(vector<string>& content, const string& filename);
    void file_err(const ifstream& infile);
    bool containSta(const string& statement, const string& flag);
    string splitFunName(const string& str);
    void InitChain(const vector<string>& content);
    void generateCode(const string& filename, const string& chainname);
    vector<string> copyCodeIntoSon(vector<string>& fatherCode, const string& filename, const string& cname);
    void copyCode(const vector<string>& fcontent, int i, int j, vector<string>& fcode);
    bool isFather(const string& str);
    vector<string> getFathersCode(const vector<string>& fname, const string& filename);
    vector<string> getDFName(const string& str, const map<string, vector<string>>& Fathers);
    bool rightCName(const string& str, const map<string, vector<string>>& Fathers);
    vector<string> combineTwoFathers(const vector<string>& one, const vector<string>& two);
    void getFName(const string& cname);
    string getCName(const map<string, vector<string>>& Fathers);
    string makeInheritContract(const map<string, vector<string>>& Fathers, const string& filename);
    void getFathersName(const string& str, vector<string>& word);
    void buildInheritChain(const string& filename);
    bool isInherit(const string& filename);
    void split(const string& str, vector<string>& vec, const char flag = ' ');
    string giveAru(const string& str);
    string getList(const string& str);
    vector<string> getTwo(const string& _str);
    string getAruList(const Node& node, const vector<string>& Content);
    string getAccName(const vector<string>& co);
    void insertAttack(vector<string>& Content, const vector<Node>& _ch, const vector<string>& new_content);
    int getContRow(const vector<string>& Content);
    vector<string> finalDeal(const vector<string>& Content);
    void StripSpace(string& _str);
public:
    //constructor
    InsertCode(const string _file_name);
    //destructor
    ~InsertCode();
    //execute
    void Execute(const int & flag);
};


#endif
