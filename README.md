# SolidityCheck
SolidityCheck说明文档

本文档介绍关于SolidityCheck的使用方法和文件组织结构

使用方法：

win10

将SolidityCheck使用visual studio编译生成可执行程序后，加入到系统的path变量中，继而可以通过命令行的形式调用。

使用命令：
SolidityCheck --help 获取帮助

SolidityCheck --d    问题检测

SolidityCheck --o	 整数溢出问题预防

SolidityCheck --r	 重入问题检测及预防

SolidityCheck --s	 设定新的昂贵的循环阈值

SolidityCheck --g 	 查看现有的昂贵的循环阈值

SolidityCheck --f    批量问题检测

文件组织结构：

SolidityCheck使用C++语言开发，包含28个头文件，以及29个源文件，除了main.cpp文件外，每一个头文件都有一个同名的对应源文件。main函数声明和定义于main.cpp中。

注意事项：
检测会生成”输入文件名_detect.report”的检测报告，插桩会生成对应的插桩文件，具体的生成文件名会打印在命令行中。其中报告的代码行号需要参考生成的”输入文件名_backup.txt”备份文件。

许可：
本程序代码及其中方法思想允许任何人和组织以无恶意的方式使用及传播，但请注明出处。
______________________________________________________________________________
SolidityCheck Description Document

This document describes the use of SolidityCheck and its file organization structure.

Usage method:

Win10

After compiling SolidityCheck into executable program using visual studio, it is added to the path variable of the system and then invoked in the form of command line.

Use commands:

Solidity Check -- Help Get Help

Solidity Check--d Problem Detection

SolidityCheck--o Integer Overflow Problem Prevention

Detection and Prevention of Solidity Check--r Reentry Problem

SolidityCheck -- s Setting New Costly Loop Threshold

SolidityCheck -- G. View existing Costly Loop threshold

Solidity Check--f Batch Problem Detection

Document organization structure:
SolidityCheck is developed in C++ language. 
It contains 28 header files and 29 source files. 
In addition to the main. CPP file, each header file has a corresponding source file with the same name. The main function is declared and defined in main. cpp.

Matters needing attention:
Detection generates the test report of "Input File Name _Detection. Report". Pile insertion generates the corresponding Pile insertion file, and the specific generated file name is printed on the command line. The line number of the reported code needs to refer to the generated backup file named _backup.txt.

Permit:
This program code and its methodological ideas allow anyone and organizations to use and disseminate in a harmless manner, but please indicate the source.
