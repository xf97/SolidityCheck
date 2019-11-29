SolidityCheck
=============
**SolidityCheck is a static code problem detection tool based on regular expressions and program instrumentation, 
which is developed for Ethereum smart contracts.**<br> SolidityCheck receives the source code files of smart contracts. <br>
First, the source code is formatted so that regular expressions can be retrieved. <br>
Then the problem statements are matched by specific regular expressions to locate the position of the problem statement. <br>
For re-entrancy vulnerabilities and integer overflow problems, SolidityCheck combines program instrumentation to prevent these two problems. <br>
Experiments show that SolidityCheck is a very effective smart contract problem detection tool with very high recall rate and detection efficiency.<br>

Usage:
------
We will publish all the source code of SolidityCheck, which is developed using Visual Studio 2017. <br>
**After compiling all source code files, the generated executable program(.exe) is added to the path 
variable of the system and invoked through the DOS.**

Functions:
----------
**Type the following commands to invoke different functions**<br>
    Get help information	---->		SolidityCheck --help<br>
    Generating contracts to prevent re-entrancy vulnerabilities		---->		SolidityCheck --r<br>
    Generating contracts to prevent integer overflow problems		---->		SolidityCheck --o<br>
    Detection of 24 other problems except integer overflow and re-entrancy vulnerabilities		---->		SolidityCheck --d<br>
    Adjust costly loop standard		---->		SolidityCheck --g<br>
    Look at existing expensive cycling standards		---->		SolidityCheck --s<br>
    Batch testing		---->		SolidityCheck --f<br>
    
License:
--------
SolidityCheck is released under the MIT License.

Note:
--------
We hide the source code for the time being, and it won't be long before they come back.



