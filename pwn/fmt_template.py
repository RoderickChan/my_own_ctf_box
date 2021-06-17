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
    pass
    

# TODO
def my_one_fmt_str_func(*, bits:int, offset:int, has_output:int, writes:dict, write_size:str) -> str:
    assert bits == 32 or bits == 64, "bits error!"
    assert write_size in ["byte", "short", "int", "long"], "write_size error!"
    # move_bits = 16 if bits == 32 else 32
    fill_dict = dict(zip(["byte", "short", "int", "long"], ["hhn", "hn", "n", "ln"]))
    and_dict = dict(zip(["byte", "short", "int", "long"], [0xff, 0xffff, 0xffffffff, 0xffffffffffffffff]))
    move_dict = dict(zip(["byte", "short", "int", "long"], [8, 16, 32, 64]))
    fmt = "a" * offset
    fill_chr = fill_dict[write_size]
    writes_list = []
    for key, val in writes.items():
        if isinstance(val, (list, tuple)):
            assert len(val) == 2, "bad writes!"
            flag = val[1]
            val = val[0]
            if flag == "hardworking":
                for i in range((bits // 8) // (move_dict[write_size] // 8)):
                    writes_list.append([key, val & and_dict[write_size]])
                    key += (move_dict[write_size] // 8)
                    val >>= move_dict[write_size]
            elif flag == "lazy":
                while val != 0:
                    writes_list.append([key, val & and_dict[write_size]])
                    key += (move_dict[write_size] // 8)
                    val >>= move_dict[write_size]
            else:
                raise ValueError("bad writes!")
        else:
            raise ValueError("bad writes!")
    print(writes_list)
            
        
        
if __name__ == '__main__':
    my_one_fmt_str_func(bits=32, offset=0, has_output=0, writes={0x12345678:(0x616263, "lazy")}, write_size="short")
        
    
    
    