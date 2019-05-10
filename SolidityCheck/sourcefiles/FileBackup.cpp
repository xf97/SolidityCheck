//The purpose of this program is to backup the formatted file 
//and provide the line number.

//source file

/*
author=__xiaofeng__
*/

//using headfiles
#include "FileBackup.h"
#include <iostream>

//FileBackup::constructor
FileBackup::FileBackup(const string _file_name, const vector<string> _content) {
	file_name = _file_name;
	content = _content;
	GetBackupName();
}

//FileBackup::destructor
FileBackup::~FileBackup() {
	file_name.clear();
	backup_file_name.clear();
	content.clear();
}

//FileBackup::GetBackupName,constructing backup file name from old name
void FileBackup::GetBackupName() {
	backup_file_name = file_name.substr(0, file_name.size() - 4);
	backup_file_name += BACKUPSUFFIX;
}

//FileBackup::OutError,handing file output error
bool FileBackup::OutError(const ofstream& out) {
	if (!out.is_open())
		return false;
	return true;
}

//FileBackup::OutBackFile,output content into back files
void FileBackup::OutBackFile() {
	ofstream outFile(backup_file_name.c_str());
	if (!OutError(outFile)) {
		cout << file_name << " file creat failed!\n";
		return;
	}

	outFile << ROWNUM << endl;

	for (int i = 0; i < content.size(); i++) {
		outFile << (i + 1) << '\t';
		outFile << content[i] << endl;
	}

	outFile.close();
	cout << "File backup completed!\n";
}
