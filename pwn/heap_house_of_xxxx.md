[toc]

## house of xxxx

此处收集各类堆利用`house of`系列方法，旨在用最简短的语言总结方法的利用效果，如果有攻击模板，还会配上攻击模板。`glibc`的源码为`libc-2.27`版本。

### house of spirit

#### 利用原理

覆盖堆指针变量，在内存可控区域构造数据，然后将可控区域释放到`fastbin`中，之后再将这块内存申请出来覆盖可控区域的其他内存内容。

#### 利用场景

- 程序中存在`free`功能，并使用`fastbin`机制
- 可以`free`掉任意地址的内存块（一般涉及到数组越界）
- 或者可以控制堆指针变量，修改堆指针变量，并释放对应的内存块

#### 利用方法

##### 利用步骤

- 伪造`fake fastbin chunk`，注意伪造好`size`，必须要使`fake chunk`落在`global_max_fast`范围内
- 修改堆指针变量，或者利用数组越界等漏洞，释放`fake chunk`
- 申请回`fake chunk`，修改其他目标区域

##### 绕过限制

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

![housrofxxx](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/housrofxxx.png)

#### 知识扩充

- 如果利用的版本为`libc-2.27.so`，即存在`tcache`机制的版本中，会先把`chunk`放在`tcachebin`中。如果对应的`tcachebin`没有放满，走这个分支的话，就不涉及到对`next_chunk`的检查，其他检查还仍然存在
- 可以先将对应的`tcachebin`放满后，在实行`house of spirit`攻击



### house of einherjar







### 参考与引用

- [简介 - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/)

