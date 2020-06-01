//
// Created by xiaofeng on 2020/6/1.
//

/*
 *This program is used to verify whether SolidityCheck has output the correct test report.
 */

#ifndef SOLIDITYCHECK_STYLECHECK_H
#define SOLIDITYCHECK_STYLECHECK_H

//Regular expressions are still used for checking.

//Report header style definition
const static string FILE_NAME = "";
const static string NUMBER_LINE_CODE = "";
const static string USE_TIME = "";
const static string TOTAL_NUMBER = "";

//Definition of report styles for various issues
//1. Private Modifier
const static string PM_STYLE_1 = "No Private Modifier.";
const static string PM_STYLE_2 = "";

//2. Costly Loop
const static string CL_STYLE_1 = "";
const static string CL_STYLE_2 = "";

//3. Balance equality
const static string BE_STYLE_1 = "";
const static string BE_STYLE_2 = "";

//4. unchecked external call
const static string UEC_STYLE_1 = "";
const static string UEC_STYLE_2 = "";

//5. tx.origin for authentication
const static string TX_STYLE_1 = "";
const static string TX_STYLE_2 = "";

//6. unsafe type inference
const static string UTI_STYLE_1 = "";
const static string UTI_STYLE_2 = "";

//7. Compiler version problem
const static string CVP_STYLE_1 = "";
const static string CVP_STYLE_2 = "";


#endif //SOLIDITYCHECK_STYLECHECK_H
