//
// Created by xiaofeng on 2019/11/29.
//

//The purpose of this program is to backup the formatted file
//and provide the line number.

//head file

/*
author=__xiaofeng__
*/

#ifndef _FILEBACKUP_H_
#define _FILEBACKUP_H_

//using headfiles
#include <fstream>
#include <string>
#include <vector>

//using namespace
using namespace std;

//const constants
const string ROWNUM = "row number ";
const string BACKUPSUFFIX = "_backup_please_refer_to_this_file_for_bug_location.txt";

//file backup class
class FileBackup {
private:
    //data
    vector<string> content;
    string file_name;
    string backup_file_name;
protected:
    bool OutError(const ofstream& out);		//output error handing
    void GetBackupName();
public:
    //constructor
    FileBackup(const string _file_name, const vector<string> _content);
    //destructor
    ~FileBackup();
    //output into backup files
    void OutBackFile();
};

#endif
