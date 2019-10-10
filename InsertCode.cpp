//This part of the program is used to provide test contracts for detecting 
//reentry vulnerabilities

//source file

/*
author=__xiaofeng__
*/

//using head file
#include "InsertCode.h"

//constructor
InsertCode::InsertCode(const string _file_name) {
	filename = _file_name;
}

//destructor
InsertCode::~InsertCode() {
	fathers.clear();
	_chain.clear();
	contract.clear();
	chainArr.clear();
	chain.clear();
	location.clear();
	code.clear();
	FatherName.clear();
	content.clear();
	index.clear();
	filename.clear();
}

//execute
void InsertCode::Execute() {
	if (isInherit(filename)) {
		buildInheritChain(filename);
		filename = makeInheritContract(fathers, filename);
	}
	getContent(content, filename);
	InitChain(content);
	if (init() == false) {
		cin.get();
		return;
	}
	getChain(content, chainArr);
	string feed_file = getTestConName(filename, appix1);
	cout << "feed_file: " << feed_file << endl;
	outToFile(content, feed_file);
	string chain_file = getTestConName(filename, appix2);
	outChain(chain, chain_file);
	cout << "Having been constructed with chains, pile insertion code is being generated....\n";
	cout << "Pile insertion position being acquired....\n";
	generateCode(feed_file, chain_file);
	cout << "Pile insertion position has been acquired and probe code is being generated....\n";
	for (auto i = location.begin(); i != location.end(); i++) {
		string bal = getBalance(content, *i);
		string acc = getAccount(content, *i, accountFlag);
		vector<string> vec = buildCode(bal, acc);
		code.push_back(vec);
	}
	cout << "The probe code has been generated and is being inserted into the specified location....\n";
	vector<string> new_content = insertCode(content);
	vector<string> final_content = finalDeal(new_content);
	cout << "The probe code has been inserted and the deposit function under test is being inserted....\n";
	cout << "please enter the right value of function's parameter.\n";
	insertAttack(final_content, chain, content);
	outToFile(final_content, feed_file);
	cout << "The deposit function is inserted and the test contract is successfully generated. Generating deployment files....\n";
	deploy(final_content);
	cout << "The deployment file was successfully generated. Generating reentry attack contract....\n";
	cout << "done! Use truffle for the next test!\n";
	return;
}

bool InsertCode::IsCallValue(const string & _str)
{
	if (_str.find(".call") > _str.size())
		return false;
	regex reg{ "(\\.)(call)(\\.)(value)(\\s)*(\\()" };
	regex reg1{ "(\\.)(gas)(\\s)*(\\()" };
	smatch s;
	smatch s1;
	if (regex_search(_str, s, reg) && !regex_search(_str, s, reg1)) {
		return true;
	}
	return false;
}

void InsertCode::AdjustCode(vector<pair<int, string>>& code)
{
	for (auto i = code.begin(); i != code.end(); i++) {
		for (auto j = i + 1; j != code.end(); j++) {
			if ((*i).first == (*j).first) {	
				string temp = (*i).second;
				(*i).second = "";
				(*i).second += (*j).second;
				(*i).second += '\n';
				(*i).second += temp;
				(*j).second = " ";
			}
		}
	}
}

string InsertCode::Re_GetConName(const string & _str)
{
	regex reg{"(\\b)(\\w)+(\\b)"};
	smatch s;
	string::const_iterator begin = _str.begin();
	string::const_iterator end = _str.end();
	int count = 0;
	while (regex_search(begin, end, s, reg)) {
		if (count == 1)
			return s[0];
		else {
			begin = s[0].second;
			count++;
		}
	}
	return "";
}

bool InsertCode::IsCIL(const string & _str)
{
	if (_str.find("contract") > _str.size() && _str.find("interface") > _str.size())
		return false;
	regex reg{ "(\\b)((contract)|(interface))(\\b)" };
	smatch s;
	if (regex_search(_str, s, reg))
		return true;
	else
		return false;
}

//function
string InsertCode::getCode(const int row, const vector<pair<int, string>>& incode) {
	for (auto i = incode.begin(); i != incode.end(); i++) {
		if (row == (*i).first && (*i).second!=" ")
			return (*i).second;
	}
	return "";
}


bool InsertCode::inRowNum(const int row, const vector<pair<int, string>>& incode) {
	for (auto i = incode.begin(); i != incode.end(); i++) {
		if (row == (*i).first)
			return true;
	}
	return false;
}

vector<pair<int, string>> InsertCode::remDup(vector<pair<int, string>> in) {
	sort(in.begin(), in.end());
	auto i = unique(in.begin(), in.end());
	vector<pair<int, string>> new_in;
	for (auto j = in.begin(); j != i; j++)
		new_in.push_back(*j);
	return new_in;
}

ostream & operator<<(ostream& os, const vector<pair<int, string>>& in) {
	for (auto i = in.begin(); i != in.end(); i++) {
		cout << (*i).first << " " << (*i).second << endl;
	}
	return os;
}


vector<string> InsertCode::insertCode(const vector<string>& Content) {
	vector<pair<int, string>> incode = mergeArr(location, code);
	//去重 
	incode = remDup(incode);
	AdjustCode(incode);
	//cout<<incode<<endl;
	vector<string> new_content;
	//	int limit=incode.size()+Content.size();
	for (int i = 0; i < Content.size(); i++) {
		if (inRowNum(i, incode)) {
			string temp = getCode(i, incode);
			new_content.push_back(temp);
			new_content.push_back(Content[i]);
			if (IsCallValue(content[i])) {
				//如果该行是尾函数的转账函数，则插入两行语句重入Aexe和Bexe的值
				new_content.push_back(ReAexe);
				new_content.push_back(ReBexe);
			}
		}
		else {
			//否则直接插入一般代码 
			new_content.push_back(Content[i]);
		}
	}
	return new_content;
}

vector<pair<int, string>> InsertCode::mergeArr(const vector<vector<int>>& Lo, const vector<vector<string>>& Co) {
	vector<pair<int, string>> inCode;
	//cout<<Lo<<endl;
	auto i = Lo.begin();
	auto j = Co.begin();
	for (; i != Lo.end() && j != Co.end(); i++, j++) {
		auto ii = (*i).begin();
		auto jj = (*j).begin();
		for (; ii != (*i).end() && jj != (*j).end(); ii++, jj++) {
			inCode.push_back(make_pair(*ii, *jj));
		}
	}
	return inCode;
}

vector<string> InsertCode::buildCode(const string& bal, const string& acc) {
	//如果Bexe是第一次赋值，则赋值，否则跳过（避免多次赋值） 
	string one = "	if(Bexe==0){\n		Bexe=" + bal + "[" + acc + "];\n		}";
	string two = "	Aexe=" + bal + "[" + acc + "];\n	require(Aexe<Bexe);";
	vector<string> vec;
	vec.push_back(one);
	vec.push_back(two);
	return vec;
}

string InsertCode::filterKeywords(const string& str) {
	//滤除以下几个在首部的关键字
	//piblic private external internal
	//memory storage 
	if (str.find("public") == 0 || str.find("memory") == 0) {
		return str.substr(6, str.size() - 6);
	}
	else if (str.find("private") == 0 || str.find("storage") == 0) {
		return str.substr(7, str.size() - 7);
	}
	else if (str.find("external") == 0 || str.find("internal") == 0) {
		return str.substr(8, str.size() - 8);
	}
	else
		return str;
}


string InsertCode::getbalance(const string& str) {
	//变量名的标志从;到)
	int right = str.length(), left = 0;
	string temp = "";
	while (str[right] != ';')
		right--;
	//右边界确定
	left = right;
	//左游标向前搜寻)
	while (str[left] != ')')
		left--;
	//截取字符串
	left++;
	temp = str.substr(left, right - left);
	//滤除写在变量名和)间的关键字 
	temp = filterKeywords(temp);
	return temp;
}



string InsertCode::ignoreBlank(const string& str) {
	string temp = "";
	for (char c : str) {
		if (!isblank(c))
			temp += c;
	}
	return temp;
}

string InsertCode::getBalance(const vector<string>& Content, const vector<int>& _lo) {
	//账本名
	string balance = "";
	//从首函数的插桩行数向上，直到最近的一个contract声明
	//将遇到的每个mapping(address=>uint)或者mapping(address=>uint256获取下来)
	//停下时，就是该合约中声明的第一个mapping(address=>uint)
	auto i = _lo[0];
	for (; i >= 0 && !containSta(Content[i], contFlag); i--) {
		string temp = Content[i];
		//对语句进行一些处理
		//滤除所有的空格
		temp = ignoreBlank(temp);
		//检查此行中是否包含了mapping声明，并且mapping在首位
		if (temp.find(mappingFlag1) == 0 || temp.find(mappingFlag2) == 0) {
			//是的话进入该语句，截取其中的账本变量名
			//cout<<temp<<endl;
			balance = getbalance(temp);
		}
	}
	if (balance.size() == 0) {
		cout << "该合约内未声明mapping(address=>uint256)型的变量。\n";
	}
	return balance;
}


string InsertCode::getAccount(const vector<string>& Content, const vector<int>& _lo, const string& flag) {
	//跳转到.call.value()一行
	string temp = Content[_lo[1]];
	int left = 0, right = 0;
	//右游标指向.call.value()的第一个字符
	right = temp.find(flag);
	//从右游标向左搜索，直到遇到不属于标识符定义的字符
	//减1是为了从.移进前端地址部分 
	left = right - 1;
	while (temp[left] == '_' || isalnum(temp[left]) || temp[left] == '.')
		left--;
	//截取，返回
	left++;
	temp = temp.substr(left, right - left);
	return temp;
}

vector<int> InsertCode::combineLocation(const int head, const int tail) {
	vector<int> location;
	location.push_back(head);
	location.push_back(tail);
	return location;
}


//该函数用于获得在尾函数中的插桩位置，返回的是插桩的最尾一行的行数
//就是.call.value()本行
int InsertCode::getTailRow(const Node& node) {
	//因为rowNum给定的是行数
	//而插入代码实际使用的是vector<string>数组
	//故减1 
	return node.rowNum - 1;
}

int InsertCode::strToInt(const string& str) {
	stringstream ss;
	//字符流吃进ss 
	ss << str;
	int i;
	//ss吐出转换后的整数
	ss >> i;
	return i;
}

Node InsertCode::isScalled(const Node& node, const vector<Node>& chain) {
	if (node.preFunc == 0) {
		//是直接调用函数，那么首函数就是尾函数，返回该Node
		return node;
	}
	//不是直接调用函数，那就寻找前置节点，直到找到调用链的尾函数节点
	Node new_node = node;
	while (new_node.preFunc != 0) {
		//寻找该节点的前置节点 
		for (auto i = chain.begin(); i != chain.end(); i++) {
			if ((*i).rowNum == new_node.preFunc) {
				//找到，重新赋值，退出for循环 
				new_node = (*i);
				break;
			}
			else
				continue;
		}
	}
	return new_node;
}

int InsertCode::getHeadRow(const string& called, const int rownum, const vector<string>& Contract) {
	//注意：数组中的元素从0起算，而行数从1起算。故差值1为正常现象。
	//注意：插入位置应该比插入的标志位置向后一行 
	for (auto i = rownum - 1; i >= 0; i--) {
		//距离被调函数距离最近的函数定义语句就一定是首函数函数头 
		if (containSta(Contract[i], funcFlag) && containSta(Contract[i], called)) {
			//找到函数头部所在一行，为了应对函数头部持续数行的情况
			//为保证插桩位置准确性，向下搜索带有'{'的一行
			int j = i;
			for (; j < rownum; j++)
				if (containSta(Contract[j], "{"))
					return j + 1;
			//如果函数头与'{'处于同一行，则该返回语句生效
			//返回函数体第一行 
			return i + 1;
		}
		else
			continue;
	}
	cout << "未找到相应函数头部。错误。\n";
	return 0;
}

void InsertCode::getContract(vector<string>& contract, const string& filename) {
	ifstream infile(filename.c_str());
	file_err(infile);
	string temp = "";
	while (getline(infile, temp))
		contract.push_back(temp);

	infile.close();
	return;
}

void InsertCode::getNodes(vector<Node>& Chain, const string& filename) {
	ifstream infile(filename.c_str());
	file_err(infile);
	/*
	保存调用链的文件格式为：
	合约名
	函数名
	插桩代码行数
	前置函数的行数
	函数可见性
	*/
	string temp = "", c_name = "", f_name = "", row_num = "", pre_func = "", c_limit = "";
	int i = 0;
	while (getline(infile, temp)) {
		if (temp == "") {
			Node node;
			node.contName = c_name;
			node.funcName = f_name;
			node.rowNum = strToInt(row_num);
			node.preFunc = strToInt(pre_func);
			node.flag = true;
			node.limit = c_limit;
			Chain.push_back(node);
			i++;
		}
		else {
			if (i % 6 == 0)
				c_name = temp;
			else if (i % 6 == 1)
				f_name = temp;
			else if (i % 6 == 2)
				row_num = temp;
			else if (i % 6 == 3)
				pre_func = temp;
			else if (i % 6 == 4)
				c_limit = temp;
			i++;
		}
	}
}

string InsertCode::getContName(const vector<string>& co) {
	string name = "";
	for (auto i = co.begin(); i != co.end(); i++) {
		//从上往下寻找，确定第一个智能合约声明的行数 
		if (containSta(*i, contFlag)) {
			//找到合约声明，分离合约名 
			name = splitContName(*i);
			return name;
		}
		else
			continue;
	}
	return name;
}


void InsertCode::deploy(const vector<string>& co) {
	//获得合约名
	string name = getContName(co);
	//生成部署文件的文件名
	string filename = "";
	filename = "n_deploy_" + name + "TEST.js";
	//生成部署文件内容
	string fileCo = makeDeploy(name);
	//输出到文件
	outStrFile(fileCo, filename);
	return;
}

void InsertCode::outStrFile(const string& co, const string& filename) {
	ofstream outfile(filename.c_str());
	file_err(outfile);
	outfile << co;
	outfile.close();
	cout << "The deployment file is generated.\n";
	return;
}

string InsertCode::makeDeploy(const string& str) {
	string co = "";
	//拼接形成实例名
	string new_str = str + "TEST";
	//生成部署文件内容
	co = "	var " + new_str + "=artifacts.require(\"" + str + "\");\n	module.exports=function(deployer){\n	deployer.deploy(" + new_str + ");\n	}";
	return co;
}

string InsertCode::getLimit(const string& str) {
	if (containSta(str, "public"))
		return "public";
	else if (containSta(str, "external"))
		return "external";
	else if (containSta(str, "internal"))
		return "internal";
	else if (containSta(str, "private"))
		return "private";
	else
		return "public";
}


void InsertCode::outChain(const vector<Node>& Chain, const string& filename) {
	ofstream outfile(filename.c_str());
	file_err(outfile);

	for (auto i = Chain.begin(); i != Chain.end(); i++) {
		outfile << (*i).contName << endl;
		//输出函数名时，不输出最后一个字符，因为保存
		//函数名时最后一个字符为(，此处不输出
		//截取函数名
		string temp = (*i).funcName.substr(0, (*i).funcName.length() - 1);
		outfile << temp << endl;
		outfile << (*i).rowNum << endl;
		outfile << (*i).preFunc << endl;
		outfile << (*i).limit << endl;
		outfile << endl;
	}
	cout << "The call chain is saved in the file " << filename << "!\n";
	outfile.close();
	return;
}

string InsertCode::getTestConName(const string& str, const string& appix) {
	int index = str.length();
	while (str[index] != '.')
		index--;
	//截取.sol前的字符串
	string pre_temp = str.substr(0, index);
	//拼接字符串
	string temp = pre_temp + appix;
	//返回拼接后的字符串
	return temp;
}

bool operator==(const Node& node1, const Node& node2) {
	if ((node1.contName == node2.contName) && (node1.funcName == node2.funcName) && (node1.preFunc == node2.preFunc) && (node1.rowNum == node2.rowNum) && (node1.limit == node2.limit))
		return true;
	else
		return false;
}


bool InsertCode::isInChain(const vector<Node>& Chain, const Node& node) {
	for (auto i = Chain.begin(); i != Chain.end(); i++) {
		if (node == (*i))
			return true;
	}
	return false;
}

bool InsertCode::init() {
	if (chainArr.size() == 0) {
		cout << "No re-entry vulnerabilities, detection ended!";
		return false;
	}
	merge(chain, chainArr);
	cout << "Building a function call chain....\n";
	return true;
}

void InsertCode::merge(vector<Node>& chainArr, const vector<Node>& arr) {
	if (arr.size() == 0)
		return;
	auto i = arr.begin();
	for (; i != arr.end(); i++)
		chainArr.push_back(*i);
	if (i == arr.end())
		return;
	else {
		cerr << "Error in interpolation!\n";
		return;
	}
}

vector<Node> InsertCode::re_search(const vector<string>& content, const Node& node) {
	vector<Node> arr;
	string head_func = "", head_cont = "", trans_sta = "";
	string see_limit = "";
	int j = 1;
	for (auto i = content.begin(); i != content.end(); i++, j++) {
		if (containSta(*i, contFlag) || containSta(*i, libFlag) || containSta(*i, interFlag))
			head_cont = splitContName(*i);
		else if (containSta(*i, funcFlag)) {
			head_func = splitFunName(*i);
			//cout<<head_func<<endl;
			//分离出函数可见性
			see_limit = getLimit(*i);
		}
		else if (containSta(*i, node.funcName) && !containSta(*i, funcFlag)) {
			//cout<<head_func<<endl;
			Node new_node;
			new_node.contName = head_cont;
			new_node.funcName = head_func;
			new_node.flag = false;
			new_node.preFunc = node.rowNum;
			new_node.limit = see_limit;
			new_node.rowNum = j;
			//判断新产生的该节点是否是
			//已有的节点
			if (!isInChain(chain, new_node)) {
				//cout<<new_node.funcName<<endl;
				arr.push_back(new_node);
			}
			else
				continue;
		}
		else
			continue;
	}
	return arr;
}

ostream & operator<<(ostream& os, const Node& node) {
	cout << "该节点内容为：\n";
	cout << "所属合约名：" << node.contName << endl;
	cout << "所属函数名：" << node.funcName << endl;
	cout << "插桩行数：" << node.rowNum << endl;
	cout << "前置函数的行数：" << node.preFunc << endl;
	cout << "函数可见性：" << node.limit << endl;
	cout << "考察标志：" << node.flag << endl;
	return os;
}

void InsertCode::getChain(const vector<string>& content, vector<Node>& arr) {
	//获得所有使用了该批次节点函数的函数节点
	vector<Node> new_arr;
	//获得前置函数
	for (auto i = arr.begin(); i != arr.end(); i++) {
		//若已经考察过，则跳过流程
		if ((*i).flag == true)
			continue;
		else {
			//考察该节点，构建该节点的调用链 
			new_arr = re_search(content, *i);
			(*i).flag = true;
		}
	}
	if (new_arr.size() == 0)
		cout << "All indirect calling functions have been acquired!\n";
	else {
		merge(chain, new_arr);
		//递归调用，通过新一轮获取的转账函数再去寻找更新一轮的函数 
		getChain(content, new_arr);
	}
	return;
}

void InsertCode::file_err(const ofstream& outfile) {
	if (!outfile.is_open()) {
		cerr << "Error output to file.\n";
		exit(1);
	}
	return;
}

void InsertCode::outToFile(const vector<string>& str, const string& filename) {
	ofstream outfile(filename.c_str());
	file_err(outfile);
	for (auto i = str.begin(); i != str.end(); i++) {
		outfile << (*i) << endl;
	}
	cout << "output to a file " << filename << ".\n";
	outfile.close();
	return;
}

string InsertCode::splitContName(const string& str) {
	int left = 0, right;
	string contract = "";
	//使得left游标进入战斗位置 
	while (isblank(str[left]))
		left++;
	while (!isblank(str[left]))
		left++;
	while (isblank(str[left]))
		left++;
	//left游标停下时，合约名左边界圈定 
	right = left;
	while (isalnum(str[right]) || str[right] == '_')
		right++;
	//right游标停下时，合约名右边界圈定
	//截取合约名 
	contract = str.substr(left, right - left);
	return contract;
}

bool InsertCode::str_in_seed(const string& str, const vector<string>& seed) {
	for (auto i = seed.begin(); i != seed.end(); i++) {
		if (containSta(str, *i))
			return true;
	}
	return false;
}

void InsertCode::getContent(vector<string>& content, const string& filename) {
	ifstream infile(filename.c_str());
	file_err(infile);

	string temp = "";
	while (getline(infile, temp)) {
		//滤除空行
		if (temp == "")
			continue;
		//滤除注释，包括单行、多行、文档注释
		else if (containSta(temp, "//"))
			continue;
		else if (containSta(temp, "/*")) {
			if (containSta(temp, "*/"))
				continue;
			else {
				while (getline(infile, temp))
					if (containSta(temp, "*/"))
						break;
			}
		}
		else
			content.push_back(temp);
	}
	infile.close();
	return;
}


void InsertCode::file_err(const ifstream& infile) {
	if (!infile.is_open()) {
		cerr << "文件操作错误，请检查智能合约文件。\n";
		exit(1);
	}
	return;
}

bool InsertCode::containSta(const string& statement, const string& flag) {
	long index = statement.find(flag);
	if (index >= 0 && index < statement.length())
		return true;
	else
		return false;
}

ostream & operator<<(ostream & os, const vector<Node>& arr) {
	for (auto i = arr.begin(); i != arr.end(); i++) {
		cout << "所属合约名：" << (*i).contName << endl;
		//输出函数名时，不输出最后一个字符，因为保存
		//函数名时最后一个字符为(，此处不输出
		//截取函数名
		string temp = (*i).funcName.substr(0, (*i).funcName.length() - 1);
		cout << "所属函数名：" << temp << endl;
		cout << "插桩行数：" << (*i).rowNum << endl;
		cout << "函数可见性：" << (*i).limit << endl;
		cout << "前置函数的行数：" << (*i).preFunc << endl;
		cout << endl;
	}
	return os;
}

string InsertCode::splitFunName(const string& str) {
	int left = 0, right;
	string function = "";
	//使得left游标进入战斗位置 
	while (isblank(str[left]))
		left++;
	while (!isblank(str[left]))
		left++;
	while (isblank(str[left]))
		left++;
	//left游标停下时，函数名左边界圈定 
	right = left;
	while (isalnum(str[right]) || str[right] == '_')
		right++;
	//right游标停下时，函数名右边界圈定
	//截取函数名
	//保留函数名的左括号，用于增强函数名的识别性 
	function = str.substr(left, right - left + 1);
	return function;
}

void InsertCode::InitChain(const vector<string>& content) {
	//逐行读取，碰到包含有function 就塞进去 
	string head_func = "", head_cont = "", trans_sta = "";
	//函数可见性
	string see_limit = "";
	int j = 1;
	for (auto i = content.begin(); i != content.end(); i++, j++) {
		if (containSta(*i, contFlag) || containSta(*i, libFlag) || containSta(*i, interFlag)) {
			//如果是合约声明语句，则将合约名剥离出
			//赋值给head_cont
			head_cont = splitContName(*i);
		}
		else if (containSta(*i, funcFlag)) {
			//如果是函数声明或者函数定义语句，则将函数名
			//剥离出赋值给head_func 
			head_func = splitFunName(*i);
			//cout<<head_func<<endl;
			//分离出函数可见性限制
			see_limit = getLimit(*i);
		}
		else if (IsCallValue(*i)) {
			//找到了转账语句，插入到记录数组中并填充各个字段的值
			Node node;
			node.contName = head_cont;
			node.funcName = head_func;
			node.rowNum = j;
			node.preFunc = 0;
			node.limit = see_limit;
			node.flag = false;
			chainArr.push_back(node);
		}
	}
	cout << "The direct call function has been fetched.\n";
	if (chainArr.size() == 0) {
		cout << "There is no direct call to the function.\n";
		return;
	}
	return;
}

ostream & operator<<(ostream& os, const vector<vector<int>>& lo) {
	for (auto i = lo.begin(); i != lo.end(); i++) {
		os << (*i) << endl;
	}
	return os;
}

ostream & operator<<(ostream& os, const vector<int>& Lo) {
	for (auto i = Lo.begin(); i != Lo.end(); i++) {
		os << (*i) << " ";
	}
	return os;
}

void InsertCode::generateCode(const string& filename, const string& chainname) {
	getNodes(_chain, chainname);
	//cout<<_chain<<endl;
	getContract(contract, filename);
	for (auto i = _chain.begin(); i != _chain.end(); i++) {
		//获得调用链首函数的插桩位置 
		int k = getHeadRow((*i).funcName, (*i).rowNum, contract);
		//获得调用链尾函数的插桩位置 
		Node node = isScalled(*i, _chain);
		int j = getTailRow(node);
		//生成插桩数组
		vector<int> lo = combineLocation(k, j);
		location.push_back(lo);
	}
	return;
}

vector<string> InsertCode::copyCodeIntoSon(vector<string>& fatherCode, const string& filename, const string& cname) {
	//文件内容数组
	vector<string> fcontent;
	getContent(fcontent, filename);
	//	cout<<fcontent.size()<<endl;
	//	cout<<"指定合约名："<<filename<<endl; 
	//	cout<<"指定子类名："<<cname<<endl;
		//step1:找到子类的所有代码
	for (int i = 0; i < fcontent.size();) {
		//		cout<<fcontent[i]<<endl;
		if (containSta(fcontent[i], contFlag) || containSta(fcontent[i], libFlag) || containSta(fcontent[i], interFlag)) {
			//分离合约名，查看其是否是我们要的子类 
//			cout<<fcontent[i]<<endl;
			vector<string> word;
			split(fcontent[i], word);
			if (containSta(word[2], "{"))
				word[2] = word[2].substr(0, word[2].size() - 1);
			if (word[2] == cname) {
				//				cout<<"我是儿子。\n";
								//找到我们要的子类
								//向下寻找下一个合约或者库声明
				int j = i + 1;
				while (j < fcontent.size() && !containSta(fcontent[j], contFlag) && !containSta(fcontent[j], libFlag) && !containSta(fcontent[j], interFlag)) {
					j++;
					//cout<<j<<endl;
				}
				//cout<<j<<endl;
				copyCode(fcontent, i, j, fatherCode);
				//给合约添加合约声明和尾部的"}"符号
				//合约声明需要去掉 is 到 { 之间的内容
				string newAnnounce;
				int index = fcontent[i].find("is");
				newAnnounce = fcontent[i].substr(0, index);
				newAnnounce.push_back('{');
				vector<string> icontent;
				icontent.push_back(newAnnounce);
				for (auto k = fatherCode.begin(); k != fatherCode.end(); k++)
					icontent.push_back(*k);
				icontent.push_back("}");
				return icontent;
			}
			else
				i++;
		}
		else
			i++;
	}
}

void InsertCode::copyCode(const vector<string>& fcontent, int i, int j, vector<string>& fcode) {
	for (int a = i + 1; a < j - 1; a++) {
		fcode.push_back(fcontent[a]);
	}
}

bool InsertCode::isFather(const string& str) {
	for (auto i = FatherName.begin(); i != FatherName.end(); i++) {
		if ((*i) == str)
			return true;
	}
	return false;
}


vector<string> InsertCode::getFathersCode(const vector<string>& fname, const string& filename) {
	vector<string> fcode;
	//第一步打开文件，将内容读取为一个vector<string>数组
	//文件内容数组
	vector<string> fcontent;
	getContent(fcontent, filename);
	//检查每一行，遇到含有合约声明的语句就检查
//	cout<<"读取文件结束。\n";
	for (int i = 0; i < fcontent.size();) {
		if (containSta(fcontent[i], contFlag) || containSta(fcontent[i], libFlag) || containSta(fcontent[i], interFlag)) {
			//分离合约名，查看其是否是我们要的父类
			vector<string> word;
			split(fcontent[i], word);
			if (containSta(word[2], "{"))
				word[2] = word[2].substr(0, word[2].size() - 1);
			//cout<<word[1]<<endl;
			//cin.get();
			if (isFather(word[2])) {
				//cout<<word[1]<<endl;
	//			cout<<"是爸爸！.\n";
				//是我们要的父类 
				//向下探查下一个合约声明，将中间所有代码作为父类合约的代码
				int j = (i + 1);
				while (j < fcontent.size() && !containSta(fcontent[j], contFlag) && !containSta(fcontent[j], libFlag) && !containSta(fcontent[j], interFlag)) {
					j++;
				}
				//cin.get();
				//cout<<i<<" "<<j<<endl;
	//			cout<<j<<endl;
				copyCode(fcontent, i, j, fcode);
				i = j - 1;
				//cin.get(); 
			}
			else
				i++;
			//错误在这里 
		}
		else
			i++;
	}
	return fcode;
}


vector<string> InsertCode::getDFName(const string& str, const map<string, vector<string>>& Fathers) {
	for (auto i = Fathers.begin(); i != Fathers.end(); i++) {
		if (str == i->first)
			return i->second;
	}
}

bool InsertCode::rightCName(const string& str, const map<string, vector<string>>& Fathers) {
	for (auto i = Fathers.begin(); i != Fathers.end(); i++) {
		if (str == i->first)
			return true;
	}
	return false;
}


vector<string> InsertCode::combineTwoFathers(const vector<string>& one, const vector<string>& two) {
	vector<string> three;
	for (auto i = one.begin(); i != one.end(); i++)
		three.push_back(*i);
	for (auto i = two.begin(); i != two.end(); i++)
		three.push_back(*i);
	return three;
}


void InsertCode::getFName(const string& cname) {
	//第一步，FatherName添加直接父类
	//cout<<"2"<<endl;
	FatherName = combineTwoFathers(FatherName, getDFName(cname, fathers));
	//将所有直接父类，再次递归调用该函数
	//cout<<"3"<<endl;
	vector<string> dfname = getDFName(cname, fathers);
	//cout<<"4"<<endl;
	if (dfname.empty())
		return;
	else {
		for (auto i = dfname.begin(); i != dfname.end(); i++)
			getFName(*i);
	}
	return;
}

string InsertCode::getCName(const map<string, vector<string>>& Fathers) {
	cout << "The following is the subclass contract name contained in the document: \n";
	for (auto i = Fathers.begin(); i != Fathers.end(); i++)
		cout << i->first << endl;
	cout << endl;
	cout << "Please select a contract from the above contract as the contract under test, and all the code of the parent class of the contract will be copied into the contract: ";
	string cname = "";
	getline(cin, cname);
	while (!rightCName(cname, Fathers)) {
		cout << "Please enter the right Contract name: ";
		getline(cin, cname);
	}
	return cname;
}

string InsertCode::makeInheritContract(const map<string, vector<string>>& Fathers, const string& filename) {
	//接收指定的最终合约
	string c_name = getCName(Fathers);
	//探查指定合约的所有父类
	getFName(c_name);
	vector<string> fathercode = getFathersCode(FatherName, filename);
	vector<string> icontent = copyCodeIntoSon(fathercode, filename, c_name);
	string returnFileName = (c_name + "_Inherit.sol");
	outToFile(icontent, returnFileName);
	return returnFileName;
}

ostream & operator<<(ostream & os, const map<string, vector<string>>& f) {
	for (auto i = f.begin(); i != f.end(); i++) {
		os << "本合约名：" << i->first << endl;
		os << "父类合约名：" << i->second << endl;
		cout << endl;
	}
	return os;
}

void InsertCode::getFathersName(const string& str, vector<string>& word) {
	//左右游标，用于框定 is ...... {的左右边界
	int left = 0, right = 0;
	left = str.find(inheritKw);
	left += 3;
	//左游标此时已到达左边界
	right = str.find("{");
	//右游标此时已到达右边界
	string temp = "";
	//截取该段字符串
	temp = str.substr(left, right - left);
	//此时以逗号为分隔符，切分字符串
	split(temp, word, ',');
	//去掉每一个元素中的空格
	for (int i = 0; i < word.size(); i++) {
		word[i] = ignoreBlank(word[i]);
	}
	return;
}

void InsertCode::buildInheritChain(const string& filename) {
	ifstream infile(filename.c_str());
	file_err(infile);

	string temp = "";
	//合约名 
	string c_name = "";
	while (getline(infile, temp)) {
		//如果是合约声明语句 
		if (IsCIL(temp)) {
			//剥离出合约名
			StripSpace(temp);
			vector <string> word;
			split(temp, word);
			//c_name = word[2];
			c_name = Re_GetConName(temp);
			//cout << "合约名：" << c_name << endl;
			//如果有{，则去除该括号
			if (containSta(c_name, "{"))
				c_name = c_name.substr(0, c_name.size() - 1);
			//剥离出基类名 
			word.clear();
			//如果是继承的子类，则剥离出父类名
			if (containSta(temp, inheritKw))
				getFathersName(temp, word);
			//word此时是基类名的结合
			else
				word.clear();
			//压入map
			fathers[c_name] = word;
		}
	}
	//cout<<fathers;
	return;
}

bool InsertCode::isInherit(const string& filename) {
	ifstream infile(filename.c_str());
	file_err(infile);
	string temp = "";
	while (getline(infile, temp)) {
		if ((containSta(temp, contFlag) || containSta(temp, libFlag) || containSta(temp, interFlag)) && containSta(temp, inheritKw)) {
			regex reg{"(\\b)((contract)|(interface))(\\b)(\\s)+(\\w)+(\\s)+(\\b)(is)(\\b)"};
			smatch s;
			if (regex_search(temp, s, reg)) {
				return true;
			}
			else
				return false;
		}
		else
			continue;
	}
	infile.close();
	return false;
}


void InsertCode::split(const string& str, vector<string>& vec, const char flag) {
	vec.clear();
	istringstream iss(str);
	string temp;

	while (getline(iss, temp, flag)) {
		vec.push_back(temp);
	}
	return;
}

string InsertCode::giveAru(const string& str) {
	//先判断，该函数调用是否需要参数
	int lkh = 0, rkh = 0;
	lkh = str.find("(");
	rkh = str.find(")");
	int i;
	for (i = lkh + 1; i < rkh; i++) {
		if (!isblank(str[i]))
			break;
	}
	if (i == rkh)
		return str + ";";
	//首先根据,的多少判断有几个参数
	int aruNum = (count(str.begin(), str.end(), ',') + 1);
	vector<string> aru;
	//截取出函数名
	int index = str.find("(");
	string f_name = str.substr(0, index);
	//截取中间参数列表部分
	int right = str.size() - 1;
	while (str[right] != ')')
		right--;
	int left = index;
	left++;
	string arulist = str.substr(left, right - left);
	cout << "function name: " << f_name << endl;
	vector<string> alist;
	//以,为分隔符进行分词
	split(arulist, alist, ',');
	//然后以分词结果为基础
	for (auto i = alist.begin(); i != alist.end(); i++) {
		vector<string> temp;
		//以空格再次分词
		temp = getTwo(*i);
		string value = "";
		cout << "Parameter types: " << temp[0] << "  " << "Name of parameter: " << temp[1] << endl;
		cout << "please enter the value of the parameter: ";
		getline(cin, value);
		if (temp[0] == "string")
			value = ("\"" + value + "\"");
		aru.push_back(value);
	}
	//拼接形成调用语句
	//函数名+(+aru的每个元素,+);
	string result = "";
	result += f_name;
	result += "(";
	for (auto i = aru.begin(); i != aru.end(); i++) {
		result += (*i);
		result += ",";
	}
	//去掉多余的,，增加);
	result = result.substr(0, result.size() - 1);
	result += ");";
	return result;
}


//用括号匹配
string InsertCode::getList(const string& str) {
	IC_Match ic;
	string list = "";
	//左游标，右游标
	int left = 0, right = 0;
	//到达function左边界
	left = str.find(funcFlag);
	//移过 function
	int i = 7;
	while (i >= 0) {
		left++;
		i--;
	}
	//掠过空格
	while (isblank(str[left]))
		left++;
	while (!ic.DoMatch(str[left])) {
		list.push_back(str[left]);
		left++;
	}
	//停下时left指向函数名左端
	/*
	//right指向函数声明语句结束
	right = str.find("{");
	//向左走，直到遇到')'
	//cout<<right<<endl;
	while (str[right] != ')') {
		right--;
		//cout<<"你好。\n";
	}
	//right停下时，标识参数列表右边界
	//截取
	right++;
	list = str.substr(left, right - left);*/
	list.push_back(')');
	return list;
}

vector<string> InsertCode::getTwo(const string & _str)
{
	vector<string> result;
	string temp = "";
	int i = 0;
	while (isblank(_str[i]))
		i++;
	while (isalnum(_str[i]) || (_str[i] == '_')) {
		temp.push_back(_str[i]);
		i++;
	}
	result.push_back(temp);
	temp.clear();
	while (isblank(_str[i]))
		i++;
	while ((isalnum(_str[i]) || (_str[i] == '_'))&&i<_str.size()) {
		temp.push_back(_str[i]);
		i++;
	}
	result.push_back(temp);
	return result;
}

string InsertCode::getAruList(const Node& node, const vector<string>& Content) {
	//该处使用的Content是用于计算行数的Content，即content
	string list = "";
	//得到行数
	int row = node.rowNum;
	//向上寻找，找到最近一行的行数声明语句
	for (int i = row; i >= 0; i--) {
		if (containSta(Content[i], funcFlag)) {
			//找到函数声明语句
			//切割，返回
			list = getList(Content[i]);
			list = giveAru(list);
			return list;
		}
	}
	return list;
}


string InsertCode::getAccName(const vector<string>& co) {
	string name = "", temp = "";
	for (int i = 0; i < co.size(); i++) {
		//先寻找到声明有mapping(address=>uint256)或者
		//mapping(address=>uint)的语句
		temp = co[i];
		//滤除空格
		temp = ignoreBlank(temp);
		//查看是否包含声明 
		if (temp.find(mappingFlag1) == 0 || temp.find(mappingFlag2) == 0) {
			//若包含，则分离变量名
			name = getbalance(temp);
			return name;
		}
	}
	return name;
}

void InsertCode::insertAttack(vector<string>& Content, const vector<Node>& _ch, const vector<string>& new_content) {
	//插入测试语句
	//获取靶函数的函数名
	vector<string> name;
	string temp_name = "";
	string para_list = "";
	//int row=0; 
	for (auto i = _ch.begin(); i != _ch.end(); i++) {
		//只选择函数可见性为public或者external的函数
		if ((*i).limit == "public" || (*i).limit == "external") {
			cout << "******************" << endl;
			para_list = getAruList(*i, new_content);
			cout << "the function call is " << para_list << endl;
			cout << "******************" << endl;
			/*
			temp_name=(*i).funcName;
			//去除funcName最后一个括号
			temp_name=temp_name.substr(0,temp_name.size()-1);
			*/
			name.push_back(para_list);
		}
		else
			continue;
	}
	//构造插入的语句
	string temp = "";
	for (auto i = name.begin(); i != name.end(); i++) {
		//拼接每一句 
		string t = "	" + (*i) + "\n";
		//cout<<t<<endl; 
		temp += t;
	}
	temp += "		}\n";
	//获取合约内的账本名
	string bal = getAccName(Content);
	//拼接存款函数内容
	string deposit_test = "	function deposit_test() public payable{\n		" + bal + "[msg.sender]+=msg.value;\n	";
	//将攻击函数插入到被测合约的最后（最后一个'}'之前）
	int i;
	string temp_ = "";
	for (i = Content.size() - 1; i >= 0; i--) {
		//cout<<Content[i]<<endl;
		if (containSta(Content[i], "}")) {
			//若包含最后一个'}'，则插入函数
			//cout<<deposit_test<<endl;
			temp_ = Content[i];
			Content[i] = deposit_test;
			Content[i] += temp;
			Content[i] += temp_;
			return;
		}
	}
	if (i == 0) {
		cerr << "插入测试用存款函数失败，请检查程序。\n";
	}
	return;
}

int InsertCode::getContRow(const vector<string>& Content) {
	for (auto i = Content.begin(); i != Content.end(); i++) {
		//从上往下寻找，确定第一个智能合约声明的行数 
		if (containSta(*i, contFlag) || containSta(*i, libFlag) || containSta(*i, interFlag)) {
			//再往下寻找{该符号的出现位置，以此确定合约体的开始
			for (auto j = i; j != Content.end(); j++)
				if (containSta(*j, "{"))
					return (j - Content.begin());
		}
		else
			continue;
	}
	return 0;
}

vector<string> InsertCode::finalDeal(const vector<string>& Content) {
	vector<string> co;
	//得到该插入代码的行数 
	int row = getContRow(Content);
	for (int i = 0; i < Content.size(); i++) {
		if (i == row) {
			co.push_back(Content[i]);
			co.push_back(AEXE);
			co.push_back(BEXE);
		}
		else
			co.push_back(Content[i]);
	}
	return co;
}

void InsertCode::StripSpace(string & _str)
{	//filter tabs
	int i = 0;
	while (isblank(_str[i]))
		i++;
	i--;
	_str = _str.substr(i, _str.size() - i);
	return;
}

IC_Match::IC_Match()
{
	count = 0;
}

IC_Match::~IC_Match() {
	brackets.clear();
	count = 0;
}

void IC_Match::Reset()
{
	count = 0;
	brackets.clear();
}

bool IC_Match::IsMatching()
{
	if (brackets.size() == 0 && count != 0)
		return true;
	return false;
}

bool IC_Match::DoMatch(const char c)
{
	if (c == '(') {
		brackets.push_back(c);
		count++;
	}
	else if (c == ')') {
		brackets.pop_back();
		if (IsMatching())
			return true;
	}
	return false;
}
