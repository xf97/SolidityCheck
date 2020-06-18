SolidityCheck
=============
<img src="./logo.jpg" alt="Logo" width="500"/>

**SolidityCheck is a static code problem analysis tool based on regular expressions and program instrumentation, which is developed for Ethereum smart contracts.**

**SolidityCheck** receives the *Solidity* source code files of smart contracts. 
First, the source code is formatted so that regular expressions can be retrieved. Then the bug statements are matched by specific regular expressions to locate the position of the problem statement. For **re-entrancy vulnerabilities** and **integer overflow bugs**, SolidityCheck combines program instrumentation to prevent these two problems. Experiments show that SolidityCheck is a very effective smart contract problem analysis tool with very high recall rate and detection efficiency.

You can find our paper [here](https://arxiv.xilesou.top/abs/1911.09425).


Quick start:
-----
We provide docker image of *SolidityCheck*, which is very convenient to obtain.

Make sure that docker is installed and the network is good. Enter the following instructions in the terminal (eg., ubuntu os):
```
sudo docker pull xf15850673022/soliditycheck:latest
sudo docker run -it xf15850673022/soliditycheck:latest
./SolidityCheck --help
```

and you're done!

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
    
#Exception workaround:
SolidityCheck sometimes has abnormalities. We found that the known abnormalities are caused by file encoding. Now we provide an effective solution:
1. Copy the **src/changeFileEncode.py** file to the same path as the contract to be tested.
2. Run the following command `python changeFileEncode.py`
3. This command will rewrite all .sol files in the folder using UTF-8 encoding.
4. Then, try to use SolidityCheck to detect the contract again.

License:
--------
SolidityCheck is released under the MIT License. You can contact me by sending email, my email address is 1150264019@qq.com.

Test data set:
--------
The experimental data set we used can also be obtained. It is packaged as **test data set.zip**.


Warning:
---------
This procedure has been applied for patent protection, any infringement of intellectual property will be taken to law.



