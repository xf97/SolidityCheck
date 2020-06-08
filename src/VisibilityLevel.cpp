//
// Created by xiaofeng on 2019/11/29.
//

// Explicitly define function visibility to prevent
//confusion

//source file

/*
author=__xiaofeng__
*/


#include "VisibilityLevel.h"
#include <iostream>

bool ViLevel::IsFun(const string & _str)
{
    if (_str.find(VL_FUN) < _str.size())
        return true;
    else if (_str.find(" constructor") < _str.size()) {
        regex reg{"^(\\s)*(constructor)(\\b)"};
        smatch s;
        if (regex_search(_str, s, reg))
            return true;
        else
            return false;
    }
    return false;
}

bool ViLevel::IsVisibility(const string & _str)
{
    if (_str.find(VL_PUBLIC) < _str.size())
        return true;
    else if (_str.find(VL_INTERNAL) < _str.size())
        return true;
    else if (_str.find(VL_PRIVATE) < _str.size())
        return true;
    else if (_str.find(VL_EXTERNAL) < _str.size())
        return true;
    else {
        return false;
    }
}

bool ViLevel::IsIllegalState(const string & _str)
{
    if (IsUint(_str))
        return true;
    else if (IsFixed(_str))
        return true;
    else if (IsAddress(_str))
        return true;
    else if (IsBool(_str))
        return true;
    else if (IsBytes(_str))
        return true;
    else if (IsArray(_str))
        return true;
    else if (IsMapping(_str))
        return true;
    return false;
}

bool ViLevel::IsMapping(const string & _str)
{
    regex reg{ VL_RE_MAPPING };
    smatch s;
    if (regex_match(_str, s, reg))
        return true;
    return false;
}

bool ViLevel::IsBool(const string & _str)
{
    regex reg{VL_RE_BOOL1};
    smatch s;
    if (regex_match(_str, s, reg)) {
        if (IsVisibility(_str) || IsVisibility1(_str))
            return false;
        else
            return true;
    }
    return false;
}

bool ViLevel::IsUint(const string & _str)
{
    regex reg{ VL_RE_UINT_INT1 };
    smatch s;
    if (regex_match(_str, s, reg)) {
        if (IsVisibility(_str) || IsVisibility1(_str))
            return false;
        else
            return true;
    }
    return false;
}

bool ViLevel::IsFixed(const string & _str)
{
    regex reg{VL_RE_UFIXED_FIXED};
    smatch s;
    if (regex_match(_str, s, reg)) {
        if (IsVisibility(_str) || IsVisibility1(_str))
            return false;
        else
            return true;
    }
    return false;
}

bool ViLevel::IsAddress(const string & _str)
{
    regex reg{ VL_RE_ADDRESS1 };
    smatch s;
    if (regex_match(_str, s, reg)) {
        if (IsVisibility(_str) || IsVisibility1(_str))
            return false;
        else
            return true;
    }
    return false;
}

bool ViLevel::IsArray(const string & _str)
{
    regex reg{VL_RE_BYTE1};
    smatch s;
    if (regex_match(_str, s, reg)) {
        if (IsVisibility(_str) || IsVisibility1(_str))
            return false;
        else
            return true;
    }
    return false;
}

bool ViLevel::IsBytes(const string & _str)
{
    if (_str.find(VL_BYTES1) < _str.size() && !IsVisibility(_str))
        return true;
    else if (_str.find(VL_STRING) < _str.size() && !IsVisibility(_str))
        return true;
    else {
        regex reg{VL_RE_ARRAY};
        smatch s;
        if (regex_match(_str, s, reg))
            return true;
        else
            return false;
    }
}

bool ViLevel::IsVisibility1(const string & _str)
{
    if (_str.find(VL_PUBLIC1) < _str.size())
        return true;
    else if (_str.find(VL_PRIVATE1) < _str.size())
        return true;
    else if (_str.find(VL_EXTERNAL1) < _str.size())
        return true;
    else if (_str.find(VL_INTERNAL1) < _str.size())
        return true;
    else
        return false;
}
bool ViLevel::IsVisibility2(const string & _str)
{
    if (_str.find(VL_PUBLIC2) < _str.size())
        return true;
    else if (_str.find(VL_PRIVATE2) < _str.size())
        return true;
    else if (_str.find(VL_EXTERNAL2) < _str.size())
        return true;
    else if (_str.find(VL_INTERNAL2) < _str.size())
        return true;
    else
        return false;
}

bool ViLevel::IsVisibility3(string _str)
{
    string str1 = _str;
    //δ֪ԭ��Bug: ����" {"�ִ��޷�ͨ��find��⣬�޸��ַ���
    if (_str.find(" {") < _str.size()) {
        str1[str1.size() - 1] = ' ';
    }
    if (str1.find(" public") == (str1.size()-10))
        return true;
    else if (str1.find(" private") == (str1.size()-11))
        return true;
    else if (str1.find(" internal") == (str1.size()-12))
        return true;
    else if (str1.find(" external") == (str1.size()-12))
        return true;
    else
        return false;
}

bool ViLevel::IsModifier(const string & _str)
{
    if (_str.find(VL_MODIFIER) < _str.size())
        return true;
    return false;
}

bool ViLevel::New_IsIllegalState(const string & _str)
{
    if (_str.find("mapping") < _str.size()) {
        regex reg{ VL_RE_NEW_MAPPING };
        regex reg1{ VL_NO_MATCH };
        smatch s;
        smatch s1;
        if (regex_search(_str, s, reg) && !regex_search(_str, s1, reg1)) {
            return true;
        }
        else
            return false;
    }
    else if (_str.find('[') < _str.size() && _str.find(']') < _str.size()) {
        regex reg{ VL_RE_NEW_ARRAY };
        regex reg1{ VL_NO_MATCH };
        smatch s;
        smatch s1;
        if (regex_search(_str, s, reg) && !regex_search(_str, s1, reg1)) {
            return true;
        }
        else
            return false;
    }
    else if (_str.find("int") < _str.size()) {
        regex reg{ VL_RE_NEW_INT };
        regex reg1{ VL_NO_MATCH };
        smatch s;
        smatch s1;
        if (regex_search(_str, s, reg) && !regex_search(_str, s1, reg1)) {
            return true;
        }
        else
            return false;
    }
    else if (_str.find("fixed") < _str.size()) {
        regex reg{ VL_RE_NEW_FIXED};
        regex reg1{ VL_NO_MATCH };
        smatch s;
        smatch s1;
        if (regex_search(_str, s, reg) && !regex_search(_str, s1, reg1)) {
            return true;
        }
        else
            return false;
    }else if(_str.find("bool")<_str.size()){
        regex reg{ VL_RE_NEW_BOOL};
        regex reg1{ VL_NO_MATCH };
        smatch s;
        smatch s1;
        if (regex_search(_str, s, reg) && !regex_search(_str, s1, reg1)) {
            return true;
        }
        else
            return false;
    }
    else if (_str.find("address") < _str.size()) {
        regex reg{VL_RE_NEW_ADDRESS };
        regex reg1{ VL_NO_MATCH };
        smatch s;
        smatch s1;
        if (regex_search(_str, s, reg) && !regex_search(_str, s1, reg1)) {
            return true;
        }
        else
            return false;
    }
    else if (_str.find("byte") < _str.size()) {
        regex reg{ VL_RE_NEW_BYTE };
        regex reg1{ VL_NO_MATCH };
        smatch s;
        smatch s1;
        if (regex_search(_str, s, reg) && !regex_search(_str, s1, reg1)) {
            return true;
        }
        else
            return false;
    }
    else if (_str.find("string") < _str.size()) {
        regex reg{ VL_RE_NEW_STRING };
        regex reg1{ VL_NO_MATCH };
        smatch s;
        smatch s1;
        if (regex_search(_str, s, reg) && !regex_search(_str, s1, reg1)) {
            return true;
        }
        else
            return false;
    }
    else
        return false;
}


ViLevel::ViLevel(const string _report_name, const vector<string> _content)
{
    report_name = _report_name;
    content = _content;
    VLName = "Implicit visibility level";
    OtherOperation = "Functions that do not have a function visibility type specified\n"
                     "are public by default. This can lead to a vulnerability if a\n"
                     "developer forgot to set the visibility and a malicious user\n"
                     "is able to make unauthorized or unintended state changes.\n"
                     "And labeling the visibility explicitly makes it easier to \n"
                     "catch incorrect assumptions about who can access the variable.\n"
                     "Bug level: warning";
}

ViLevel::~ViLevel() {
    report_name.clear();
    content.clear();
    VLName.clear();
    OtherOperation.clear();
    row_number.clear();
}

string ViLevel::MakeReport(const vector<int>& _row_number) {
    if (_row_number.empty()) {
        return "No implicit visibility level.\n\n";
    }
    string _report = "";
    _report += "[Bug 14]\n";
    _report += "bug name: ";
    _report += VLName;
    _report += '\n';
    _report += "number of bugs: ";
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


int ViLevel::GetNumber() {
    return row_number.size();
}

vector<int> ViLevel::GetRowNumber() {
    return row_number;
}

void ViLevel::Detection()
{
    //todo
    for (int i = 0; i < content.size(); i++) {
        if (IsFun(content[i])) {
            if (content[i].find(';') < content[i].size() && IsVisibility1(content[i])) {
                cout << content[i] << endl;
                continue;
            }
            else if (IsVisibility(content[i])) {
                continue;
            }
            else
                row_number.push_back((i + 1));
        }
        else if (IsIllegalState(content[i])) {
            if (IsVisibility(content[i])) {
                continue;
            }
            else {
                row_number.push_back((i + 1));
            }
        }
        else
            continue;
    }
}

void ViLevel::Re_Detection(VL_Match& vl)
{
    for (int i = 0; i < content.size(); ) {
        if (IsFun(content[i])) {
            if (content[i].find(';') < content[i].size() && (IsVisibility1(content[i]) || IsVisibility(content[i]))) {
                i++;
            }
            else if (IsVisibility(content[i])) {
                vl.Reset();
                while (!vl.IsMatch())
                    vl.Match(content[i++]);
            }
            else if (content[i].find(';') < content[i].size()) {
                row_number.push_back((i + 1));
                i++;
            }
            else {
                row_number.push_back((i + 1));
                vl.Reset();
                while (!vl.IsMatch())
                    vl.Match(content[i++]);
            }
        }
        else if (IsModifier(content[i])) {
            vl.Reset();
            while (!vl.IsMatch())
                vl.Match(content[i++]);
        }
        else if (IsIllegalState(content[i])) {
            row_number.push_back((i + 1));
            i++;
        }
        else
            i++;
    }
}

void ViLevel::New_Re_Detection(VL_Match & vl)
{
    for (int i = 0; i < content.size(); ) {
        if (IsFun(content[i])) {
            /*
            if (content[i].find(';') < content[i].size() && (IsVisibility1(content[i]) || IsVisibility(content[i]))) {
                cout << 1 << endl;
                i++;
            }
            else if (IsVisibility(content[i]) || IsVisibility2(content[i])) {
                cout << 2 << endl;
                vl.Reset();
                while (!vl.IsMatch())
                    vl.Match(content[i++]);
            }
            else if (content[i].find(';') < content[i].size()) {
                cout << 3 << endl;
                row_number.push_back((i + 1));
                i++;
            }*/
            regex reg{ "(\\b)((private)|(public)|(internal)|(external))(\\b)" };
            smatch s;
            if (content[i].find(';') < content[i].size() && (IsVisibility1(content[i]) || IsVisibility(content[i]))) {
                i++;
            }
            else if (IsVisibility(content[i]) || IsVisibility2(content[i]) || IsVisibility3(content[i])) {
                vl.Reset();
                while (!vl.IsMatch())
                    vl.Match(content[i++]);
            }
            else if (content[i].find(';') < content[i].size()) {
                row_number.push_back((i + 1));
                i++;
            }
            else {
                row_number.push_back((i + 1));
                vl.Reset();
                while (!vl.IsMatch())
                    vl.Match(content[i++]);
            }
            /*
            if (regex_search(content[i], s, reg)) {
                if (content[i].find(";") < content[i].size())
                    i++;
                else {
                    vl.Reset();
                    while (!vl.IsMatch()) {
                        cout << "match: " << content[i] << endl;
                        vl.Match(content[i++]);
                    }
                }
            }
            else {
                row_number.push_back((i + 1));
                vl.Reset();
                while (!vl.IsMatch()) {
                    cout << "match: " << content[i] << endl;
                    vl.Match(content[i++]);
                }
            }*/
        }
        else if (IsModifier(content[i])) {
            vl.Reset();
            while (!vl.IsMatch())
                vl.Match(content[i++]);
        }
        else if (New_IsIllegalState(content[i])) {
            row_number.push_back((i + 1));
            i++;
        }
        else
            i++;
    }
}

void VL_Match::Match(const string & _str)
{
    for (char c : _str) {
        if (c == '{') {
            count++;
            brackets.push_back('{');
        }
        else if (c == '}') {
            brackets.pop_back();
        }
    }
}
