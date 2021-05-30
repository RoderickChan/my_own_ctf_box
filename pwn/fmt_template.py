#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : fmt_template.py
@Time    : 2021/05/30 21:40:00
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : None
'''

"""
以下涉及到格式化字符串的攻击模板，包括：
    1、利用pwntools来生成格式化字符串
    2、手写字符串
    3、自己写一套格式化字符串生成函数
"""
from pwn import *

def get_fmt_str_by_pwntools(offset:int, ):
    """"利用pwntools的格式化字符串"""
    context.update(arch="i386")
    