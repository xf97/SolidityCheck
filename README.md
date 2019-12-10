SolidityCheck
=============
![avatar](logo.jpg)
**SolidityCheck is a static code problem analysis tool based on regular expressions and program instrumentation, which is developed for Ethereum smart contracts.**

**SolidityCheck** receives the *Solidity* source code files of smart contracts. 
First, the source code is formatted so that regular expressions can be retrieved. Then the bug statements are matched by specific regular expressions to locate the position of the problem statement. For **re-entrancy vulnerabilities** and **integer overflow bugs**, SolidityCheck combines program instrumentation to prevent these two problems. Experiments show that SolidityCheck is a very effective smart contract problem analysis tool with very high recall rate and detection efficiency.



Usage:
------
**We provide the user manual of SolidityCheck, which introduces the various functions of SolidityCheck. The Chinese version has been released. The English version will be available later.**

Functions:
----------
**Type the following commands to invoke different functions**<br>
    Get help information	---->		SolidityCheck --help<br>
    Generating contracts to prevent re-entrancy vulnerabilities		---->		SolidityCheck --r<br>
    Generating contracts to prevent integer overflow problems		---->		SolidityCheck --o<br>
    Detection of 18 other problems except integer overflow and re-entrancy vulnerabilities		---->		SolidityCheck --d<br>
    Adjust costly loop standard		---->		SolidityCheck --g<br>
    Look at existing expensive cycling standards		---->		SolidityCheck --s<br>
    Batch testing		---->		SolidityCheck --f<br>
    Generate contracts to detect reentrant vulnerabilities	---->		SolidityCheck --ir<br>
    
License:
--------
SolidityCheck is released under the MIT License.

Note:
--------
I uploaded the test data set of the paper experiment, some contracts are stored on my another device, so the data set uploaded today is incomplete, and I will upload the complete data set tomorrow. 

Warning:
---------
This procedure has been applied for patent protection, any infringement of intellectual property will be taken to law.



