//
// Created by xiaofeng on 2019/11/29.
//

//
// Created by xiaofeng on 2019/11/29.
//

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
void InsertCode::Execute(const int & flag) {
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
    if(flag){
        insertAttack(final_content, chain, content);
    }
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
    //ȥ��
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
                //���������β������ת�˺���������������������Aexe��Bexe��ֵ
                new_content.push_back(ReAexe);
                new_content.push_back(ReBexe);
            }
        }
        else {
            //����ֱ�Ӳ���һ�����
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
    //���Bexe�ǵ�һ�θ�ֵ����ֵ�����������������θ�ֵ��
    string one = "	if(Bexe==0){\t //insert code\n		Bexe=" + bal + "[" + acc + "];\t //insert code\n		}";
    string two = "	Aexe=" + bal + "[" + acc + "];\t //insert code\n	require(Aexe<Bexe);\t //insert code";
    vector<string> vec;
    vec.push_back(one);
    vec.push_back(two);
    return vec;
}

string InsertCode::filterKeywords(const string& str) {
    //�˳����¼������ײ��Ĺؼ���
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
    //�������ı�־��;��)
    int right = str.length(), left = 0;
    string temp = "";
    while (str[right] != ';')
        right--;
    //�ұ߽�ȷ��
    left = right;
    //���α���ǰ��Ѱ)
    while (str[left] != ')')
        left--;
    //��ȡ�ַ���
    left++;
    temp = str.substr(left, right - left);
    //�˳�д�ڱ�������)��Ĺؼ���
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
    //�˱���
    string balance = "";
    //���׺����Ĳ�׮�������ϣ�ֱ�������һ��contract����
    //��������ÿ��mapping(address=>uint)����mapping(address=>uint256��ȡ����)
    //ͣ��ʱ�����Ǹú�Լ�������ĵ�һ��mapping(address=>uint)
    auto i = _lo[0];
    for (; i >= 0 && !containSta(Content[i], contFlag); i--) {
        string temp = Content[i];
        //��������һЩ����
        //�˳����еĿո�
        temp = ignoreBlank(temp);
        //���������Ƿ������mapping����������mapping����λ
        if (temp.find(mappingFlag1) == 0 || temp.find(mappingFlag2) == 0) {
            //�ǵĻ��������䣬��ȡ���е��˱�������
            //cout<<temp<<endl;
            balance = getbalance(temp);
        }
    }
    if (balance.size() == 0) {
        cout << "�ú�Լ��δ����mapping(address=>uint256)�͵ı�����\n";
    }
    return balance;
}


string InsertCode::getAccount(const vector<string>& Content, const vector<int>& _lo, const string& flag) {
    //��ת��.call.value()һ��
    string temp = Content[_lo[1]];
    int left = 0, right = 0;
    //���α�ָ��.call.value()�ĵ�һ���ַ�
    right = temp.find(flag);
    //�����α�����������ֱ�����������ڱ�ʶ��������ַ�
    //��1��Ϊ�˴�.�ƽ�ǰ�˵�ַ����
    left = right - 1;
    while (temp[left] == '_' || isalnum(temp[left]) || temp[left] == '.')
        left--;
    //��ȡ������
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


//�ú������ڻ����β�����еĲ�׮λ�ã����ص��ǲ�׮����βһ�е�����
//����.call.value()����
int InsertCode::getTailRow(const Node& node) {
    //��ΪrowNum������������
    //���������ʵ��ʹ�õ���vector<string>����
    //�ʼ�1
    return node.rowNum - 1;
}

int InsertCode::strToInt(const string& str) {
    stringstream ss;
    //�ַ����Խ�ss
    ss << str;
    int i;
    //ss�³�ת���������
    ss >> i;
    return i;
}

Node InsertCode::isScalled(const Node& node, const vector<Node>& chain) {
    if (node.preFunc == 0) {
        //��ֱ�ӵ��ú�������ô�׺�������β���������ظ�Node
        return node;
    }
    //����ֱ�ӵ��ú������Ǿ�Ѱ��ǰ�ýڵ㣬ֱ���ҵ���������β�����ڵ�
    Node new_node = node;
    while (new_node.preFunc != 0) {
        //Ѱ�Ҹýڵ��ǰ�ýڵ�
        for (auto i = chain.begin(); i != chain.end(); i++) {
            if ((*i).rowNum == new_node.preFunc) {
                //�ҵ������¸�ֵ���˳�forѭ��
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
    //ע�⣺�����е�Ԫ�ش�0���㣬��������1���㡣�ʲ�ֵ1Ϊ��������
    //ע�⣺����λ��Ӧ�ñȲ���ı�־λ�����һ��
    for (auto i = rownum - 1; i >= 0; i--) {
        //���뱻��������������ĺ�����������һ�����׺�������ͷ
        if (containSta(Contract[i], funcFlag) && containSta(Contract[i], called)) {
            //�ҵ�����ͷ������һ�У�Ϊ��Ӧ�Ժ���ͷ���������е����
            //Ϊ��֤��׮λ��׼ȷ�ԣ�������������'{'��һ��
            int j = i;
            for (; j < rownum; j++)
                if (containSta(Contract[j], "{"))
                    return j + 1;
            //�������ͷ��'{'����ͬһ�У���÷��������Ч
            //���غ������һ��
            return i + 1;
        }
        else
            continue;
    }
    cout << "δ�ҵ���Ӧ����ͷ��������\n";
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
    ������������ļ���ʽΪ��
    ��Լ��
    ������
    ��׮��������
    ǰ�ú���������
    �����ɼ���
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
        //��������Ѱ�ң�ȷ����һ�����ܺ�Լ����������
        if (containSta(*i, contFlag)) {
            //�ҵ���Լ�����������Լ��
            name = splitContName(*i);
            return name;
        }
        else
            continue;
    }
    return name;
}


void InsertCode::deploy(const vector<string>& co) {
    //��ú�Լ��
    string name = getContName(co);
    //���ɲ����ļ����ļ���
    string filename = "";
    filename = "n_deploy_" + name + "TEST.js";
    //���ɲ����ļ�����
    string fileCo = makeDeploy(name);
    //������ļ�
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
    //ƴ���γ�ʵ����
    string new_str = str + "TEST";
    //���ɲ����ļ�����
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
        //���������ʱ����������һ���ַ�����Ϊ����
        //������ʱ���һ���ַ�Ϊ(���˴������
        //��ȡ������
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
    //��ȡ.solǰ���ַ���
    string pre_temp = str.substr(0, index);
    //ƴ���ַ���
    string temp = pre_temp + appix;
    //����ƴ�Ӻ���ַ���
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
            //����������ɼ���
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
            //�ж��²����ĸýڵ��Ƿ���
            //���еĽڵ�
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
    cout << "�ýڵ�����Ϊ��\n";
    cout << "������Լ����" << node.contName << endl;
    cout << "������������" << node.funcName << endl;
    cout << "��׮������" << node.rowNum << endl;
    cout << "ǰ�ú�����������" << node.preFunc << endl;
    cout << "�����ɼ��ԣ�" << node.limit << endl;
    cout << "�����־��" << node.flag << endl;
    return os;
}

void InsertCode::getChain(const vector<string>& content, vector<Node>& arr) {
    //�������ʹ���˸����νڵ㺯���ĺ����ڵ�
    vector<Node> new_arr;
    //���ǰ�ú���
    for (auto i = arr.begin(); i != arr.end(); i++) {
        //���Ѿ������������������
        if ((*i).flag == true)
            continue;
        else {
            //����ýڵ㣬�����ýڵ�ĵ�����
            new_arr = re_search(content, *i);
            (*i).flag = true;
        }
    }
    if (new_arr.size() == 0)
        cout << "All indirect calling functions have been acquired!\n";
    else {
        merge(chain, new_arr);
        //�ݹ���ã�ͨ����һ�ֻ�ȡ��ת�˺�����ȥѰ�Ҹ���һ�ֵĺ���
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
    //ʹ��left�α����ս��λ��
    while (isblank(str[left]))
        left++;
    while (!isblank(str[left]))
        left++;
    while (isblank(str[left]))
        left++;
    //left�α�ͣ��ʱ����Լ����߽�Ȧ��
    right = left;
    while (isalnum(str[right]) || str[right] == '_')
        right++;
    //right�α�ͣ��ʱ����Լ���ұ߽�Ȧ��
    //��ȡ��Լ��
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
        //�˳�����
        if (temp == "")
            continue;
            //�˳�ע�ͣ��������С����С��ĵ�ע��
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
        cerr << "�ļ����������������ܺ�Լ�ļ���\n";
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
        cout << "������Լ����" << (*i).contName << endl;
        //���������ʱ����������һ���ַ�����Ϊ����
        //������ʱ���һ���ַ�Ϊ(���˴������
        //��ȡ������
        string temp = (*i).funcName.substr(0, (*i).funcName.length() - 1);
        cout << "������������" << temp << endl;
        cout << "��׮������" << (*i).rowNum << endl;
        cout << "�����ɼ��ԣ�" << (*i).limit << endl;
        cout << "ǰ�ú�����������" << (*i).preFunc << endl;
        cout << endl;
    }
    return os;
}

string InsertCode::splitFunName(const string& str) {
    int left = 0, right;
    string function = "";
    //ʹ��left�α����ս��λ��
    while (isblank(str[left]))
        left++;
    while (!isblank(str[left]))
        left++;
    while (isblank(str[left]))
        left++;
    //left�α�ͣ��ʱ����������߽�Ȧ��
    right = left;
    while (isalnum(str[right]) || str[right] == '_')
        right++;
    //right�α�ͣ��ʱ���������ұ߽�Ȧ��
    //��ȡ������
    //�����������������ţ�������ǿ��������ʶ����
    function = str.substr(left, right - left + 1);
    return function;
}

void InsertCode::InitChain(const vector<string>& content) {
    //���ж�ȡ������������function ������ȥ
    string head_func = "", head_cont = "", trans_sta = "";
    //�����ɼ���
    string see_limit = "";
    int j = 1;
    for (auto i = content.begin(); i != content.end(); i++, j++) {
        if (containSta(*i, contFlag) || containSta(*i, libFlag) || containSta(*i, interFlag)) {
            //����Ǻ�Լ������䣬�򽫺�Լ�������
            //��ֵ��head_cont
            head_cont = splitContName(*i);
        }
        else if (containSta(*i, funcFlag)) {
            //����Ǻ����������ߺ���������䣬�򽫺�����
            //�������ֵ��head_func
            head_func = splitFunName(*i);
            //cout<<head_func<<endl;
            //����������ɼ�������
            see_limit = getLimit(*i);
        }
        else if (IsCallValue(*i)) {
            //�ҵ���ת����䣬���뵽��¼�����в��������ֶε�ֵ
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
        //��õ������׺����Ĳ�׮λ��
        int k = getHeadRow((*i).funcName, (*i).rowNum, contract);
        //��õ�����β�����Ĳ�׮λ��
        Node node = isScalled(*i, _chain);
        int j = getTailRow(node);
        //���ɲ�׮����
        vector<int> lo = combineLocation(k, j);
        location.push_back(lo);
    }
    return;
}

vector<string> InsertCode::copyCodeIntoSon(vector<string>& fatherCode, const string& filename, const string& cname) {
    //�ļ���������
    vector<string> fcontent;
    getContent(fcontent, filename);
    //	cout<<fcontent.size()<<endl;
    //	cout<<"ָ����Լ����"<<filename<<endl;
    //	cout<<"ָ����������"<<cname<<endl;
    //step1:�ҵ���������д���
    for (int i = 0; i < fcontent.size();) {
        //		cout<<fcontent[i]<<endl;
        if (containSta(fcontent[i], contFlag) || containSta(fcontent[i], libFlag) || containSta(fcontent[i], interFlag)) {
            //�����Լ�����鿴���Ƿ�������Ҫ������
//			cout<<fcontent[i]<<endl;
            vector<string> word;
            split(fcontent[i], word);
            if (containSta(word[2], "{"))
                word[2] = word[2].substr(0, word[2].size() - 1);
            if (word[2] == cname) {
                //				cout<<"���Ƕ��ӡ�\n";
                //�ҵ�����Ҫ������
                //����Ѱ����һ����Լ���߿�����
                int j = i + 1;
                while (j < fcontent.size() && !containSta(fcontent[j], contFlag) && !containSta(fcontent[j], libFlag) && !containSta(fcontent[j], interFlag)) {
                    j++;
                    //cout<<j<<endl;
                }
                //cout<<j<<endl;
                copyCode(fcontent, i, j, fatherCode);
                //����Լ��Ӻ�Լ������β����"}"����
                //��Լ������Ҫȥ�� is �� { ֮�������
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
    //��һ�����ļ��������ݶ�ȡΪһ��vector<string>����
    //�ļ���������
    vector<string> fcontent;
    getContent(fcontent, filename);
    //���ÿһ�У��������к�Լ���������ͼ��
//	cout<<"��ȡ�ļ�������\n";
    for (int i = 0; i < fcontent.size();) {
        if (containSta(fcontent[i], contFlag) || containSta(fcontent[i], libFlag) || containSta(fcontent[i], interFlag)) {
            //�����Լ�����鿴���Ƿ�������Ҫ�ĸ���
            vector<string> word;
            split(fcontent[i], word);
            if (containSta(word[2], "{"))
                word[2] = word[2].substr(0, word[2].size() - 1);
            //cout<<word[1]<<endl;
            //cin.get();
            if (isFather(word[2])) {
                //cout<<word[1]<<endl;
                //			cout<<"�ǰְ֣�.\n";
                //������Ҫ�ĸ���
                //����̽����һ����Լ���������м����д�����Ϊ�����Լ�Ĵ���
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
            //����������
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
    //��һ����FatherName���ֱ�Ӹ���
    //cout<<"2"<<endl;
    FatherName = combineTwoFathers(FatherName, getDFName(cname, fathers));
    //������ֱ�Ӹ��࣬�ٴεݹ���øú���
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
    //����ָ�������պ�Լ
    string c_name = getCName(Fathers);
    //̽��ָ����Լ�����и���
    getFName(c_name);
    vector<string> fathercode = getFathersCode(FatherName, filename);
    vector<string> icontent = copyCodeIntoSon(fathercode, filename, c_name);
    string returnFileName = (c_name + "_Inherit.sol");
    outToFile(icontent, returnFileName);
    return returnFileName;
}

ostream & operator<<(ostream & os, const map<string, vector<string>>& f) {
    for (auto i = f.begin(); i != f.end(); i++) {
        os << "����Լ����" << i->first << endl;
        os << "�����Լ����" << i->second << endl;
        cout << endl;
    }
    return os;
}

void InsertCode::getFathersName(const string& str, vector<string>& word) {
    //�����α꣬���ڿ� is ...... {�����ұ߽�
    int left = 0, right = 0;
    left = str.find(inheritKw);
    left += 3;
    //���α��ʱ�ѵ�����߽�
    right = str.find("{");
    //���α��ʱ�ѵ����ұ߽�
    string temp = "";
    //��ȡ�ö��ַ���
    temp = str.substr(left, right - left);
    //��ʱ�Զ���Ϊ�ָ������з��ַ���
    split(temp, word, ',');
    //ȥ��ÿһ��Ԫ���еĿո�
    for (int i = 0; i < word.size(); i++) {
        word[i] = ignoreBlank(word[i]);
    }
    return;
}

void InsertCode::buildInheritChain(const string& filename) {
    ifstream infile(filename.c_str());
    file_err(infile);

    string temp = "";
    //��Լ��
    string c_name = "";
    while (getline(infile, temp)) {
        //����Ǻ�Լ�������
        if (IsCIL(temp)) {
            //�������Լ��
            StripSpace(temp);
            vector <string> word;
            split(temp, word);
            //c_name = word[2];
            c_name = Re_GetConName(temp);
            //cout << "��Լ����" << c_name << endl;
            //�����{����ȥ��������
            if (containSta(c_name, "{"))
                c_name = c_name.substr(0, c_name.size() - 1);
            //�����������
            word.clear();
            //����Ǽ̳е����࣬������������
            if (containSta(temp, inheritKw))
                getFathersName(temp, word);
                //word��ʱ�ǻ������Ľ��
            else
                word.clear();
            //ѹ��map
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
    //���жϣ��ú��������Ƿ���Ҫ����
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
    //���ȸ���,�Ķ����ж��м�������
    int aruNum = (count(str.begin(), str.end(), ',') + 1);
    vector<string> aru;
    //��ȡ��������
    int index = str.find("(");
    string f_name = str.substr(0, index);
    //��ȡ�м�����б���
    int right = str.size() - 1;
    while (str[right] != ')')
        right--;
    int left = index;
    left++;
    string arulist = str.substr(left, right - left);
    cout << "function name: " << f_name << endl;
    vector<string> alist;
    //��,Ϊ�ָ������зִ�
    split(arulist, alist, ',');
    //Ȼ���Էִʽ��Ϊ����
    for (auto i = alist.begin(); i != alist.end(); i++) {
        vector<string> temp;
        //�Կո��ٴηִ�
        temp = getTwo(*i);
        string value = "";
        cout << "Parameter types: " << temp[0] << "  " << "Name of parameter: " << temp[1] << endl;
        cout << "please enter the value of the parameter: ";
        getline(cin, value);
        if (temp[0] == "string")
            value = ("\"" + value + "\"");
        aru.push_back(value);
    }
    //ƴ���γɵ������
    //������+(+aru��ÿ��Ԫ��,+);
    string result = "";
    result += f_name;
    result += "(";
    for (auto i = aru.begin(); i != aru.end(); i++) {
        result += (*i);
        result += ",";
    }
    //ȥ�������,������);
    result = result.substr(0, result.size() - 1);
    result += ");";
    return result;
}


//������ƥ��
string InsertCode::getList(const string& str) {
    IC_Match ic;
    string list = "";
    //���α꣬���α�
    int left = 0, right = 0;
    //����function��߽�
    left = str.find(funcFlag);
    //�ƹ� function
    int i = 7;
    while (i >= 0) {
        left++;
        i--;
    }
    //�ӹ��ո�
    while (isblank(str[left]))
        left++;
    while (!ic.DoMatch(str[left])) {
        list.push_back(str[left]);
        left++;
    }
    //ͣ��ʱleftָ���������
    /*
    //rightָ��������������
    right = str.find("{");
    //�����ߣ�ֱ������')'
    //cout<<right<<endl;
    while (str[right] != ')') {
        right--;
        //cout<<"��á�\n";
    }
    //rightͣ��ʱ����ʶ�����б��ұ߽�
    //��ȡ
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
    //�ô�ʹ�õ�Content�����ڼ���������Content����content
    string list = "";
    //�õ�����
    int row = node.rowNum;
    //����Ѱ�ң��ҵ����һ�е������������
    for (int i = row; i >= 0; i--) {
        if (containSta(Content[i], funcFlag)) {
            //�ҵ������������
            //�и����
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
        //��Ѱ�ҵ�������mapping(address=>uint256)����
        //mapping(address=>uint)�����
        temp = co[i];
        //�˳��ո�
        temp = ignoreBlank(temp);
        //�鿴�Ƿ��������
        if (temp.find(mappingFlag1) == 0 || temp.find(mappingFlag2) == 0) {
            //������������������
            name = getbalance(temp);
            return name;
        }
    }
    return name;
}

void InsertCode::insertAttack(vector<string>& Content, const vector<Node>& _ch, const vector<string>& new_content) {
    //����������
    //��ȡ�к����ĺ�����
    vector<string> name;
    string temp_name = "";
    string para_list = "";
    //int row=0;
    for (auto i = _ch.begin(); i != _ch.end(); i++) {
        //ֻѡ�����ɼ���Ϊpublic����external�ĺ���
        if ((*i).limit == "public" || (*i).limit == "external") {
            cout << "******************" << endl;
            para_list = getAruList(*i, new_content);
            cout << "the function call is " << para_list << endl;
            cout << "******************" << endl;
            /*
            temp_name=(*i).funcName;
            //ȥ��funcName���һ������
            temp_name=temp_name.substr(0,temp_name.size()-1);
            */
            name.push_back(para_list);
        }
        else
            continue;
    }
    //�����������
    string temp = "";
    for (auto i = name.begin(); i != name.end(); i++) {
        //ƴ��ÿһ��
        string t = "	" + (*i) + "\t //insert code\n";
        //cout<<t<<endl;
        temp += t;
    }
    temp += "		}\n";
    //��ȡ��Լ�ڵ��˱���
    string bal = getAccName(Content);
    //ƴ�Ӵ�������
    string deposit_test = "	function deposit_test() public payable{\t //insert code\n		" + bal + "[msg.sender]+=msg.value;\t //insert code\n	";
    //�������������뵽�����Լ��������һ��'}'֮ǰ��
    int i;
    string temp_ = "";
    for (i = Content.size() - 1; i >= 0; i--) {
        //cout<<Content[i]<<endl;
        if (containSta(Content[i], "}")) {
            //���������һ��'}'������뺯��
            //cout<<deposit_test<<endl;
            temp_ = Content[i];
            Content[i] = deposit_test;
            Content[i] += temp;
            Content[i] += temp_;
            return;
        }
    }
    if (i == 0) {
        cerr << "��������ô���ʧ�ܣ��������\n";
    }
    return;
}

int InsertCode::getContRow(const vector<string>& Content) {
    for (auto i = Content.begin(); i != Content.end(); i++) {
        //��������Ѱ�ң�ȷ����һ�����ܺ�Լ����������
        if (containSta(*i, contFlag) || containSta(*i, libFlag) || containSta(*i, interFlag)) {
            //������Ѱ��{�÷��ŵĳ���λ�ã��Դ�ȷ����Լ��Ŀ�ʼ
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
    //�õ��ò�����������
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
