//
// Created by xiaofeng on 2019/11/25.
//

//This program is used to arrange the
//source code in order to better analyze.

//source file

/*
author=__xiaofeng__
*/

//using headfiles
#include "ArrangeCode.h"
#include <iostream>

//FileIO's constructor
FileIO::FileIO(const string& _filename) {
    filename = _filename;
}

//FileIO's constructor
FileIO::FileIO() {
    cout << "enter the file name: ";
    string _filename;
    getline(cin, _filename);
    filename = _filename;
}

//FileIO's destructor
FileIO::~FileIO() {
    //wipe data
    str_content.clear();
    vec_content.clear();
    filename.clear();
}

//read-in error handing
bool FileIO::InError(const ifstream& in) {
    if (!in.is_open())
        return false;
    return true;
}

//output error handing
bool FileIO::OutError(const ofstream& out) {
    if (!out.is_open())
        return false;
    return true;
}

//return origin contract's name
string FileIO::getContractName() {
    return filename;
}

//return file name
string FileIO::outFileName() {
    return filename;
}

//read-in to vector and string
void FileIO::ReadIn() {
    ifstream inFile(filename);

    if (!InError(inFile)) {
        cout << filename << " is not properly opened!" << endl;
        return;
    }

    //get vector
    string temp = "";
    //getline drops '\n'
    while (getline(inFile, temp)) {
        temp.insert(0, " ");
        vec_content.push_back(temp);
        str_content += temp;
        str_content += '\n';
    }
    temp.clear();
    cout << filename << " is readed out!\n";
    inFile.close();
}

void FileIO::outVectorToFile(const string& _filename, const vector<string> &_content) {
    ofstream fout;
    fout.open(_filename,ios_base::out);
    if(fout.is_open())
    {
        for(auto i=_content.begin(),end=_content.end(); i!=end; ++i)
        {
            if ((*i).find('\n')){
                fout<<(*i);
            }
            else{
                fout<<(*i)<<endl;
            }
        }
    }
    fout.close();
}

//output to vector
vector<string> FileIO::OutVector() {
    return vec_content;
}

//output to string
string FileIO::OutString() {
    return str_content;
}

//return code rows
int FileIO::GetRows() {
    return vec_content.size();
}

//print vector<string>
void FileIO::PrintVec() {
    for (auto i = vec_content.begin(); i != vec_content.end(); i++) {
        cout << (*i) << endl;
    }
}

//out string to a file
void FileIO::OutToFile(const string& filename, const string& new_content) {
    ofstream outFile(filename.c_str());
    if (!OutError(outFile)) {
        cout << filename << " file creat failed!\n";
        return;
    }

    outFile << new_content;
    outFile.close();
    cout << "File formatting completed.\n";
}

//independent output for vector<string>
ostream & operator<<(ostream& os, const vector<string>& vec) {
    for (auto i = vec.begin(); i != vec.end(); i++)
        os << (*i) << endl;
    return os;
}

//ArrangeCode::constructor
ArrangeCode::ArrangeCode(const string _old_content, const string _old_name) {
    old_content = _old_content;
    old_name = _old_name;
    GetNewName(_old_name);
    GetReportName(_old_name);
    //cout<<old_content<<endl;
}

//ArrangeCode::OutOldName,return old_name
string ArrangeCode::OutOldName() {
    return old_name;
}

//ArrangeCode::OutNewName,return new_name
string ArrangeCode::OutNewName() {
    return new_name;
}

//ArrangeCode::OutReport,return detect report file name
string ArrangeCode::OutReport() {
    return detect_result;
}

//ArrangeCode::getNewName,for named formatting source code file
void ArrangeCode::GetNewName(const string& _old_name) {
    new_name = _old_name.substr(0, _old_name.size() - 4);
    new_name += FORMATSUFFIX;
}

//ArrangeCode::destructor
ArrangeCode::~ArrangeCode() {
    old_content.clear();
    old_name.clear();
    new_content.clear();
    new_name.clear();
}

//filter single line and document comments
void ArrangeCode::FilterSingle(const string& _old_str, string& _new_str) {
    for (int i = 0; i < _old_str.size();) {
        if (_old_str[i] == '/' && _old_str[i + 1] == '/') {
            while (_old_str[i] != '\n')
                i++;
            i += 1;
        }
        else {
            _new_str += _old_str[i];
            i++;
        }
    }
}

bool ArrangeCode::IsFor(const string & _str)
{
    string temp;
    int i = 0;
    while (isblank(_str[i]))
        i++;
    temp = _str.substr(i, _str.size() - i);
    if ((temp.find("for ") < temp.size() || temp.find("for(") < temp.size()) && (temp.find("for")==0))
        return true;
    return false;
}

vector<string> ArrangeCode::F_Blank(vector<string>& _content)
{
    vector<string> temp;
    for (auto i = _content.begin(); i != _content.end(); i++) {
        if (!IsBlankLine(*i))
            temp.push_back(*i);
    }
    return temp;
}

//ArrangeCode::GetReportName,generating name of test report
void ArrangeCode::GetReportName(const string& _old_name) {
    detect_result = _old_name.substr(0, _old_name.size() - 4);
    detect_result += REPORTSUFFIX;
}

//ArrangeCode::Output new content
string ArrangeCode::OutString() {
    return new_content;
}

//ArrangeCode::Output old content
string ArrangeCode::OutOldString() {
    return old_content;
}

//ArrangeCode::FilterMul,to filter multiline comments
void ArrangeCode::FilterMul(const string& _old_str, string& _new_str) {
    _new_str.clear();
    for (int i = 0; i < _old_str.size();) {
        if (_old_str[i] == '/' && _old_str[i + 1] == '*') {
            while (!(_old_str[i] == '*' && _old_str[i + 1] == '/'))
                i++;
            i += 2;
        }
        else {
            _new_str += _old_str[i];
            i++;
        }
    }
}

//ArrangeCode::ArrangeConDef.arrange contract/interface/library definitions/declarations
//contract definitions/declarations must are in one line
void ArrangeCode::ArrangeConDef(const string& type, string& _old_str) {
    int index = 0;
    while (true) {
        index = _old_str.find(type, index);
        if (index < _old_str.size()) {
            while (_old_str[index] != '{' && _old_str[index] != ';') {
                if (_old_str[index] == '\n')
                    _old_str[index] = ' ';
                index++;
            }
        }
        else
            break;
    }
    //cout<<_old_str<<endl;
}

//ArrangeCode::Seprate.Make the last'}'of the contract/interface/library body alone
void ArrangeCode::Seprate(string& _old_str) {
    //get "contract"/"library"/"interface" index
    vector<int> index = GetConIndex(_old_str);
    int temp_index;
    //execute
    for (int i = 1; i < index.size(); i++) {
        //Look forward for '}'
        temp_index = index[i];
        while (_old_str[temp_index] != '}')
            temp_index--;
        if (_old_str[temp_index - 1] == ' ') {
            _old_str[temp_index - 1] = '\n';
        }
        else {
            _old_str[temp_index] = '\n';
            _old_str.insert(temp_index + 1, "}");
        }
    }
    //handling the last contract or library or interface
    temp_index = _old_str.size()-1;
    _old_str[temp_index] = '\n';
    while (_old_str[temp_index] != '}' && temp_index>=0)
        temp_index--;
    _old_str[temp_index] = '\n';
    _old_str.push_back('}');
}

void ArrangeCode::ArrangeFunDef(const string& type, string& _old_str) {
    int index = 0;
    while (1) {
        index = _old_str.find(type, index);
        if (index < _old_str.size()) {
            while (_old_str[index] != '{' && _old_str[index] != ';') {
                if (_old_str[index] == '\n')
                    _old_str[index] = ' ';
                index++;
            }
        }
        else
            break;
    }
}

//ArrangeCode::FilterBlankLine,filter the blank lines in the vec_content
void ArrangeCode::FilterBlankLine() {
    vector<string> temp;
    for (auto i = vec_content.begin(); i != vec_content.end(); i++) {
        if ((*i).empty() || IsBlankLine((*i)))
            continue;
        else
            temp.push_back((*i));
    }
    vec_content.clear();
    vec_content = temp;
    temp.clear();
}


//ArrangeCode::Strip,strip surplus spaces in whole vector<string>
void ArrangeCode::Strip(vector<string>& vec) {
    for (auto i = vec_content.begin(); i != vec_content.end(); i++)
        StripSpace((*i));
}

string ArrangeCode::JustOneLine(const string & _old_str)
{
    string temp = "";
    for (char c : _old_str) {
        if (c==';'|| c == '{' || c == '}') {
            temp.push_back(c);
            temp.push_back('\n');
        }
        else if (c == '\n')
            temp.push_back(' ');
        else
            temp.push_back(c);
    }
    return temp;
}

vector<string> ArrangeCode::SpecialFor(vector<string>& vec)
{
    regex reg{ AR_RE_FOR };
    smatch s;
    vector<int> index;
    vector<string> temp;
    for (int i = 0; i < vec.size();i++) {
        if (IsFor(vec[i])) {
            vec[i] += vec[i + 1];
            vec[i] += vec[i + 2];
            NoMiddleN(vec[i]);
            index.push_back(i);
        }
    }
    for (int i = 0; i < vec.size();) {
        if (IsForIndex(index, i)) {
            if (!IsBlankLine(vec[i]))
                temp.push_back(vec[i]);
            i += 3;
        }
        else {
            if (!IsBlankLine(vec[i]))
                temp.push_back(vec[i]);
            ++i;
        }
    }
    return temp;
}

void ArrangeCode::NoMiddleN(string & _str)
{
    for (int i = 0; i < _str.size(); i++) {
        if (_str[i] == '\n')
            _str[i] = ' ';
    }
}

bool ArrangeCode::IsForIndex(const vector<int>& _index, const int i)
{
    for (auto j = _index.begin(); j != _index.end(); j++) {
        if ((*j) == i)
            return true;
    }
    return false;
}


//ArrangeCode::StripSpace,strip surplus spaces in one line
void ArrangeCode::StripSpace(string& _str) {
    //filter tabs
    for (int i = 0; i < _str.size(); i++)
        if (_str[i] == '\t')
            _str[i] = ' ';
    int next = 0, tail;
    while (_str[next] == ' ')
        next++;
    tail = next;
    while (next < _str.size()) {
        if (_str[next] != ' ') {
            _str[tail] = _str[next];
            tail++;
        }
        else if (_str[next] == ' ' && _str[next - 1] != ' ') {
            _str[tail] = _str[next];
            tail++;
        }
        next++;
    }
    //deleted elements
    _str.erase(_str.begin() + tail, _str.end());
    //cout<<_str<<endl;
}

void ArrangeCode::ArrangeLoopDef(const string& type, string& _old_str) {
    int index = 0;
    while (1) {
        index = _old_str.find(type, index);
        if (index < _old_str.size()) {
            while (_old_str[index] != '{' && _old_str[index] != ';') {
                if (_old_str[index] == '\n')
                    _old_str[index] = ' ';
                index++;
            }
        }
        else
            break;
    }
}

//ArrangeCode::OutVec,return vec_content
vector<string> ArrangeCode::OutVec() {
    return vec_content;
}

//ArrangeCode::GetConIndex,get the key words "contract"/"interface"/"library" index in the string,and then return a vector<int>
vector<int> ArrangeCode::GetConIndex(const string& _old_str) {
    vector<int> vec_index;
    //find "contract" index
    int index = 0;
    while (1) {
        index = _old_str.find(CON, index);
        if (index < _old_str.size()) {
            vec_index.push_back(index);
            index++;
        }
        else
            break;
    }
    //find "library" index
    index = 0;
    while (1) {
        index = _old_str.find(LIB, index);
        if (index < _old_str.size()) {
            vec_index.push_back(index);
            index++;
        }
        else
            break;
    }
    //find "interface" index
    index = 0;
    while (1) {
        index = _old_str.find(INT, index);
        if (index < _old_str.size()) {
            vec_index.push_back(index);
            index++;
        }
        else
            break;
    }
    //sort,from small to big
    sort(vec_index.begin(), vec_index.end());
    return vec_index;
}

//C++ split
void ArrangeCode::split(const string& _str, vector<string>& vec, const char flag) {
    vec.clear();
    istringstream iss(_str);
    string temp = "";

    while (getline(iss, temp, flag))
        vec.push_back(temp);
    temp.clear();
}

//ArrangeCode::StrToVec,Each \n split line becomes an element of the vector<string>
void ArrangeCode::StrToVec(const string& content) {
    split(content, vec_content, '\n');
    /*
    for(auto i = vec_content.begin(); i != vec_content.end(); i++){
        cout<<(*i)<<endl;
    }*/
    FilterBlankLine();
    Strip(vec_content);
    vec_content=SpecialFor(vec_content);
    FilterBlankLine();
    //cout<<"*******************"<<endl;
    /*for(auto i = vec_content.begin(); i != vec_content.end(); i++){
        cout<<(*i)<<endl;
    }*/
    /*
    for(auto i = vec_content.begin(); i != vec_content.end(); i++){
        cout<<(*i)<<endl;
    }*/
}

//ArrangeCode::VecToStr,input:vector<string>,output:string
string ArrangeCode::VecToStr(const vector<string>& _vec) {
    string temp = "";
    for (auto i = _vec.begin(); i != _vec.end(); i++) {
        //cout<<(*i)<<endl;
        if (IsBlankLine(*i))
            continue;
        else {
            //cout<<(*i)<<endl;
            temp.append((*i));
            temp += '\n';
        }
    }
    return temp;
}

//ArrangeCode::IsBlankLine,This function is used to determine whether a line is composed of all spaces.
bool ArrangeCode::IsBlankLine(const string& _str) {
    for (int i = 0; i < _str.size(); i++)
        if (!isblank(_str[i]) && _str[i]!='\n')
            return false;
    return true;
}

//ArrangeCode::ArrangeRemain,the rest of the statements are completed in one line
void ArrangeCode::ArrangeRemain(const string& _old_str, string& _new_str) {
    //each line can only end with'{'or'}' or';'.
    _new_str.clear();
    for (int i = 0; i < _old_str.size(); i++) {
        if (_old_str[i] == '{' || _old_str[i] == '}' || _old_str[i] == ';') {
            _new_str += _old_str[i];
            _new_str += '\n';
        }
        else if (_old_str[i] == '\n') {
            _new_str += ' ';
        }
        else
            _new_str += _old_str[i];
    }
    //cout<<_new_str<<endl;
}

//ArrangeCode::formatcode
void ArrangeCode::FormatCode() {
    //1.filter single line comments
    FilterSingle(old_content, new_content);
    //cout<<new_content<<endl;
    //2.filter multiline comments
    FilterMul(new_content, old_content);
    //cout<<old_content<<endl;
    //JustOneLine(old_content);
    //cout<<old_content<<endl;
    //3.arrange contract/interface/library definitions/declarations
    ArrangeConDef(CON, old_content);
    //cout<<old_content<<endl;
    ArrangeConDef(INT, old_content);
    ArrangeConDef(LIB, old_content);
    //4.arrange function/modifier definitions/declarations
    ArrangeFunDef(FUN, old_content);
    //cout<<"*************"<<endl;
    //cout<<old_content<<endl;
    ArrangeFunDef(MOD, old_content);
    ArrangeFunDef(EVE, old_content);
    //5.arrange the if/while/for statements
    ArrangeLoopDef(IF1, old_content);
    ArrangeLoopDef(IF2, old_content);
    ArrangeLoopDef(FOR1, old_content);
    ArrangeLoopDef(FOR2, old_content);
    ArrangeLoopDef(WHILE1, old_content);
    ArrangeLoopDef(WHILE2, old_content);
    //6.Make the last'}'of the contract/interface/library body alone.
    Seprate(old_content);
    //7.Make the remaining statements complete in one line
    ArrangeRemain(old_content, new_content);
    //8. Patching discovered vulnerabilities
    //cout<<new_content<<endl;
    old_content = JustOneLine(new_content);
    //cout<<old_content<<endl;
    StripSpace(old_content);
}


