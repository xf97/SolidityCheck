SolidityCheck
=============
<img src="./logo.jpg" alt="Logo" width="500"/>

**SolidityCheck is a static code problem analysis tool based on regular expressions and program instrumentation, which is developed for Ethereum smart contracts.**

**SolidityCheck** receives the *Solidity* source code files of smart contracts. 
First, the source code is formatted so that regular expressions can be retrieved. Then the bug statements are matched by specific regular expressions to locate the position of the problem statement. For **re-entrancy vulnerabilities** and **integer overflow bugs**, SolidityCheck combines program instrumentation to prevent these two problems. Experiments show that SolidityCheck is a very effective smart contract problem analysis tool with very high recall rate and detection efficiency.

You can find our paper [here](https://arxiv.xilesou.top/abs/1911.09425).

Usage:
------
**We provide the user manual of SolidityCheck, which introduces the various functions of SolidityCheck. The Chinese version has been released. The English version will be available later.**

You can find the Chinese manual [here](https://github.com/xf97/SolidityCheck/blob/master/SolidityCheck使用手册.pdf).

Features:
----------
**Type the following commands to invoke different functions**

   
Get help information
    ```
    $ SolidityCheck --help
    ```

Generating contracts to prevent re-entrancy vulnerabilities		
    ```
    $ SolidityCheck --r
    ```

Generating contracts to prevent integer overflow problems
    ```
    $ SolidityCheck --o
    ```

Detection of 18 other problems except integer overflow and re-entrancy vulnerabilities		
    ```
    $ SolidityCheck --d
    ```

Adjust costly loop standard	
    ```
    $ SolidityCheck --g
    ```

Look at existing costly loop standard
    ```
    $ SolidityCheck --s
    ```

Batch testing
    ```
    $ SolidityCheck --f
    ```

Generate contracts to detect re-entrancy vulnerabilities
	```
	$ SolidityCheck --ir
    ```
    
License:
--------
SolidityCheck is released under the MIT License. You can contact me by sending email, my email address is 1150264019@qq.com.

Note:
--------
I uploaded the test data set of the paper experiment, some contracts are stored on my another device, so the data set uploaded today is incomplete, and I will upload the complete data set tomorrow. 

Warning:
---------
This procedure has been applied for patent protection, any infringement of intellectual property will be taken to law.



