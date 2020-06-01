#!/usr/bin/python
#-*- coding:utf-8 -*-

'''
__author__ = xiaofeng
__date__ = 2020/6/1
'''

import os

class autoTest:
	def __init__(self):
		self.command = "./SolidityCheck --f contractPath.txt"
		self.updateContracts = "python ./getContractPath.py"
		self.deleteFailFile = "rm "

	def run(self):
		result = self.exeCommand(self.command)
		filename = self.getDeletedFile(result.read())
		#result_deleted  = self.exeCommand(self.deleteFailFile + filename)
		#result_update = self.exeCommand(self.updateContracts)


	def exeCommand(self, _command):
		return os.popen(_command)

	def getDeletedFile(self, _content):
		print(type(_content))
		content_list = _content.split("\n")
		content_length = len(content_list)
	#	time = 3
		#for i in range(content_length-1, -1, -1):
		print(content_list[len(content_list) - 4])





print("hello world")
at = autoTest()
at.run()
