[toc]

## house of xxxx

此处收集各类堆利用`house of`系列方法，旨在用最简短的语言总结方法的利用效果，如果有攻击模板，还会配上攻击模板。`glibc`的源码为`libc-2.27`版本。

### house of spirit

#### 利用原理

该方法主要针对`fastbin`，通过覆盖堆指针变量，在内存可控区域构造数据，然后将可控区域释放到`fastbin`中，之后再将这块内存申请出来控制可控区域上方或下方的其他内存内容。

#### 利用场景

- 程序中存在`free`功能，并使用`fastbin`机制
- 可以`free`掉任意地址的内存块（一般涉及到数组越界）
- 或者可以控制堆指针变量，修改堆指针变量，并释放对应的内存块

#### 利用方法

##### 利用步骤

- 伪造`fake fastbin chunk`，使其能绕过系统检查，注意要使`fake chunk`落在`global_max_fast`范围内
- 修改堆指针变量，或者利用数组越界等漏洞，释放`fake chunk`
- 申请回`fake chunk`，修改其他目标区域

##### 限制条件

需要注意以下几点：

- `fake chunk`的 `ISMMAP`位不能为`1`，`free`中对`mmap`申请出来的`chunk`，会单独处理
- `fake chunk`地址需要`8`字节或`16`字节对齐
- `fake chunk`的`size`大小需要满足`fastbin`范围内，也需要对齐
- `fake chunk`的`next chunk`的大小不能小于 `2 * SIZE_SZ`，同时也不能大于`av->system_mem`
- `fake chunk`对应的`fastbin`链表头部不能是该`fake chunk`，即不能构成`double free`的情况。

##### 源码阅读

直接看`_int_free`的源码：`malloc\malloc.c:4138`

```c
/* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size))) // 判断size，以及是否对齐
    malloc_printerr ("free(): invalid size");

  check_inuse_chunk(av, p);
······
if ((unsigned long)(size) <= (unsigned long)(get_max_fast ()) // 判断是否处于fastbin chunk范围内

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {
// 判断next chunk的size
    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	bool fail = true;
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might result in a false positive.  Redo the test after
	   getting the lock.  */
	if (!have_lock)
	  {
	    __libc_lock_lock (av->mutex);
	    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
	    __libc_lock_unlock (av->mutex);
	  }

	if (fail)
	  malloc_printerr ("free(): invalid next size (fast)");
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    atomic_store_relaxed (&av->have_fastchunks, true);
    unsigned int idx = fastbin_index(size); // 根据size寻找fastbin的索引
    fb = &fastbin (av, idx); // 找到对应的bin

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2; // 取头节点的chunk

    if (SINGLE_THREAD_P)
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
	if (__builtin_expect (old == p, 0)) // 判断当前释放的chunk是否与头节点chunk一样
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = old;
	*fb = p;
      }
    else
      do
	{
	  /* Check that the top of the bin is not the record we are going to
	     add (i.e., double free).  */
	  if (__builtin_expect (old == p, 0)) // 判断当前释放的chunk是否与头节点chunk一样
	    malloc_printerr ("double free or corruption (fasttop)");
	  p->fd = old2 = old; // 当前chunk插入链表
	}
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
	     != old2);

    /* Check that size of fastbin chunk at the top is the same as
       size of the chunk that we are adding.  We can dereference OLD
       only if we have the lock, otherwise it might have already been
       allocated again.  */
    if (have_lock && old != NULL
	&& __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
      malloc_printerr ("invalid fastbin entry (free)");
  }
```

从源码中可以解释，为啥需要绕过那么多的限制。此外，在`__libc_free`函数中，对`mmap`的内存会单独处理。

#### 利用效果

图示利用效果：

![housrofspirit1](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/housrofspirit1.png)

#### 知识扩充

- 如果利用的版本为`libc-2.27.so`，即存在`tcache`机制的版本中，会先把`chunk`放在`tcachebin`中。如果对应的`tcachebin`没有放满，走这个分支的话，就不涉及到对`next_chunk`的检查，其他检查还仍然存在

- 对于含有`tcache`的版本，可以先将对应的`tcachebin`放满后，再施行`house of spirit`攻击

- 如果伪造的`chunk`的大小大于`global_max_fast`，那么当释放假的`chunk`的时候，布局应该如下：

  ![image-20210627175358157](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210627175358157.png)

  这是因为，对于将要放置在`unsorted bin`中的`chunk`，首先会尝试后向合并，然后尝试前向合并，合并过程会触发`unlink`，之后才会放置在`unsorted bin`中。

### house of einherjar



### house of roman

#### 利用原理

使用`fastbin attack`与`unsorted bin`结合，低字节爆破`12bit`修改`main_arena+88`这个地址为`one_gadget`，通过劫持`malloc_hook`或其他可控的`hook`变量，最终获取`shell`。

#### 利用场景

该方法需要爆破`12bit`，成功率为`1 / 4096`，不到万不得已，最好不要使用，因为可能需要爆破很久。

- 程序中不存在泄露地址的函数，或者无法泄露地址
- 存在`UAF`，或者能残留地址
- 能够使用`fastbin attack`和`unsorted bin attack`

#### 利用方法

##### 利用步骤

- 首先使用`fastbin`和`unsorted bin`构造堆布局，使得`fastbin 0x70`这条链最后一个元素的`fd`指向`main_arena+88`。这一步，有两种布局方式。

  - 方法一：
    - 释放`0x70`的`chunk A`
    - 修改已释放的`chunk A`的`size`为`0x91`，做好堆布局
    - 再释放`1`次`chunk A`，即可完成堆布局
  - 方法二：
    - 依次释放两个`0x70`的`chunk A`和`chunk B`，此时的链为`B ---> A`。
    - 释放一个`0x90`的`chunk C`，其会被放置在`unsorted bin`中，`fd`和`bk`会被更新为`main_arena+ 88`
    - 分配走`0x20`大小的`chunk D` ，则此时`chunk C`大小为`0x70`，`fd`和`bk`不变
    - `partial overwrite`此时的`chunk B`的`fd`指针，使其指向`chunk C`即可完成堆布局

  ![housrofxxx-housr of roman](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/housrofxxx-housr%20of%20roman.png)

- 爆破`4bit`修改`main_arena + 88`这个值，修改为`&__malloc_hook - 0x23`，即可在`__malloc_hook`上方分配`0x70`的`fake chunk`

- 使用`fastbin`分配到`fake chunk`，此时已经能修改`__malloc_hook`的值

- 使用`unsorted bin attack`将`__malloc_hook`写为`unsorted_chunks (av)`，也就是`main_arena + 88`

- 利用上面分配的`fake chunk`爆破`8bit`修改`main_arena + 88`为`one_gadget`

- 再次调用`malloc`时即可获取`shell`

##### 限制条件

如果满足利用场景的话，基本上不存在限制条件。唯一可能很坑的是，每个`one_gadget`最终都不滿足触发条件。这个时候，可以观察一下寄存器的值，看哪些寄存器可用，再找找合适的`gadget`。

#### 利用效果

![housrofxxx-housr of roman2](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/housrofxxx-housr%20of%20roman2.png)

#### 知识扩充

- `house of roman`主要是提供了一种思想：利用已有的程序地址，结合`partial overwrite`绕过随机化。所以，除了去修改`__malloc_hook`，还有劫持`IO_FILE`的`vtable`再结合`partial overwrite`控制`IO`类函数的执行流的方法。其思路均与`house of roman`一致
  - 充分利用`malloc`不会清空信息的特性来构造堆布局，而`calloc`的`chunk`，若其`M`位为`1`，则也不会清空`chunk`

### 参考与引用

- [简介 - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/)

