//
// Created by xiaofeng on 2020/6/2.
//

/*
 *This program is used to verify whether SolidityCheck has output the correct test report.
 */

//source file

#include "StyleCheck.h"
#include <iostream>

//constructor
styleCheck::styleCheck(const string _report_name) {
    FileIO io(_report_name);
    io.ReadIn();
    report_content = io.OutVector();
}

//destructor
styleCheck::~styleCheck() {
    report_content.clear();
    //report_list.clear();
}

//check main function: run
void styleCheck::run() {
    int lineNumber = 0;
    if(checkHeader() == false){
        flag = false;
        cout<<"不符合. "<<endl;
    }
    else {
        cout << "符合标准." << endl;
    }
    /*
    for(;lineNumber < report_content.size(); i++){

    }
     */
}

bool styleCheck::getFlag() {
    return flag;
}

//check report header
bool styleCheck::checkHeader() {
    regex reg1{FILE_NAME};
    regex reg2{NUMBER_LINE_CODE};
    regex reg3{USE_TIME};
    regex reg4{TOTAL_NUMBER};
    smatch s1;
    smatch s2;
    smatch s3;
    smatch s4;
    if (regex_search(report_content[0], s1, reg1) == false){
        cout<<1<<endl;
        return false;
    }
    if(regex_search(report_content[1], s2, reg2) == false){
        cout<<2<<endl;
        return false;
    }
    if(regex_search(report_content[2], s3, reg3) == false){
        cout<<3<<endl;
        return false;
    }
    if(regex_search(report_content[3], s4, reg4) == false){
        cout<<4<<endl;
        return false;
    }
    return true;
}

//check report single bug
bool styleCheck::checkSingleBug(const int &_number) {
    return true;
}

