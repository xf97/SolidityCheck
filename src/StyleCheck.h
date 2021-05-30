//
// Created by xiaofeng on 2020/6/1.
//

/*
 *This program is used to verify whether SolidityCheck has output the correct test report.
 */

//head file

#ifndef SOLIDITYCHECK_STYLECHECK_H
#define SOLIDITYCHECK_STYLECHECK_H

#include <regex>
#include "ArrangeCode.h"


using  namespace std;

//Regular expressions are still used for checking.

//Report header style definition
const static string FILE_NAME = "file name: ((0x)|(0X))[0-9A-Fa-f]{40}\\.sol$";
const static string NUMBER_LINE_CODE = "number of lines of code: [0-9]+$";
const static string USE_TIME = "use time: [0-9\\.]+ s\\.$";
const static string TOTAL_NUMBER = "total number of vulnerabilities: [0-9]+$";

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

//8. time dependence
const static string TD_STYLE_1 = "";
const static string TD_STYLE_2 = "";

//9. integer division
const static string ID_STYLE_1 = "";
const static string ID_STYLE_2 = "";

//10.  locked money.
const static string IM_STYLE_1 = "";
const static string IM_STYLE_2 = "";

//11. byte[]
const static string BYTE_STYLE_1 = "";
const static string BYTE_STYLE_2 = "";

//12. redundant refusal of payment
const static string RR_STYLE_1 = "";
const static string RR_STYLE_2 = "";

//13. Style guide violation
const static string SGV_STYLE_1 = "";
const static string SGV_STYLE_2 = "";

//14. Implicity visibility level
const static string IVL_STYLE_1 = "";
const static string IVL_STYLE_2 = "";

//15. using fixed point number type
const static string UF_STYLE_1 = "";
const static string UF_STYLE_2 = "";

//16. Token API violation
const static string TAV_STYLE_1 = "";
const static string TAV_STYLE_2 = "";

//17. dos by external contract
const static string DBE_STYLE_1 = "";
const static string DBE_STYLE_2 = "";

//18. Missing Constructor
const static string MC_STYLE_1 = "";
const static string MC_STYLE_2 = "";

class styleCheck {
private:
    vector<string> report_content;    //report content
    //vector<string> report_list;       //split report content to list
    bool flag;
protected:
    //void contentToList();
public:
    styleCheck(const string _report_name);  //constructor
    ~styleCheck();  //destructor
    void getReport();    //get report content
    bool checkHeader();
    bool checkSingleBug(const int& _number);
    void run();
    bool getFlag();
};
#endif //SOLIDITYCHECK_STYLECHECK_H
