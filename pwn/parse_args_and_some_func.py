'''
==========================================================================================
本脚本为pwn题所编写，利用click模块配置命令行参数，
能方便地进行本地调试和远程解题。
本地命令示例：
    python3 exp.py filename --tmux 1 --gdb-breakpoint 0x804802a --gdb-breakpoint printf
    python3 exp.py filename -t 1 -gb 0x804802a -gb printf
    python3 exp.py filename -t 1 -gs "x /12gx \$rebase(0x202080)" -sf 0 -pl "warn"
    python3 exp.py filename -w 1 -gb printf
    即可开始本地调试,并且会断在地址或函数处。
    注意：先启动tmux后，--tmux才会有效。安装了open-wsl.exe，-w参数才会有效。

远程命令示例：
    python3 exp.py filename -i 127.0.0.1 -p 22164
    可以连接指定的IP和端口。目前在刷buuctf上的题，所以填了默认ip，只指定端口即可。

修改后，本脚本只提供对外接口，使用方式为：from parse_args_and_some_func import *
通过all_parsed_args访问所有的参数，包括本地或远程的io
==========================================================================================

'''
print(__doc__)

from pwn import *
import click
from collections import OrderedDict
import sys
import os
import time
import functools
# 所有的参数
all_parsed_args =OrderedDict([('filename', None), # 要执行的二进制文件名，或路径
            ('debug_enable', 1), # 是否开启调试模式
            ('tmux_enable', 0), # 是否开启tmux终端，使用gdb.attach(io)的方式
            ('open_wsl_exe', 0), # open-wsl.exe是否开启
            ('gdb_breakpoint', None), # 当tmux或者open-wsl.exe开启的时候，b开头的断点的设置，是一个list
            ('gdb_script', None), # tmux或者open-wsl.exe开启的时候，自定义脚本的设置
            ('ip', None), # 远程连接的IP
            ('port', None), # 远程连接的端口
            ('local_log', 1), # 本地LOG函数是否开启
            ('pwn_log_level', 'debug'), # pwntools的log级别设置
            ('stop_function_enable', 1),  # STOP方法是否开启
            ('io', None), # process or remote object
            ('cur_elf', None) # current elf file
            ])

# 不打印的名单，不会通过print_parsed_args_info打印出来
not_print_list = ('io', 'cur_elf')

# 默认的远程ip, 只指定port的时候会默认赋值
__default_ip = 'node3.buuoj.cn'

def __change():
    '''
    只有DEBUG开启的时候，才有tmux或者open-wsl.exe
    IP和PORT给定后，必须关闭DEBUG, 这个级别最高
    '''
    global all_parsed_args
    if all_parsed_args['port'] or all_parsed_args['ip']:
        if all_parsed_args['ip'] is None:
            all_parsed_args['ip'] = __default_ip
        all_parsed_args['debug_enable'] = 0
    
    if not all_parsed_args['debug_enable']:
        all_parsed_args['tmux_enable'] = 0
        all_parsed_args['open_wsl_exe'] = 0
    
    if (not all_parsed_args['tmux_enable']) and (not all_parsed_args['open_wsl_exe']):
        all_parsed_args['gdb_breakpoint'] = None
        all_parsed_args['gdb_script'] = None
    
    # tmux的优先级高一些
    if all_parsed_args['tmux_enable']:
        all_parsed_args['open_wsl_exe'] = 0
    
    
def __check():
    '''
    检查参数是否合法
    '''
    assert not (all_parsed_args['filename'] is None and all_parsed_args['debug_enable'] == 1), "at least 'filename' or 'debug_enable'"
    assert not (all_parsed_args['port'] is None and all_parsed_args['debug_enable'] == 0), "at least 'port' or 'debug_enable'"
    assert not (all_parsed_args['ip'] is not None and all_parsed_args['port'] is None), "at least 'port'"


def print_parsed_args_info(log_black_list:bool=False, log_none:bool=False):
    '''
    打印所有的参数信息
    '''
    click.echo('=' * 90)
    click.echo(' [+] Args info:\n')
    for key, val in all_parsed_args.items():
        if (not log_black_list) and (key in not_print_list):
            continue
        if (not log_none) and (not key):
            continue 
        click.echo('  {}: {}'.format(key, val))
    click.echo('=' * 90)


def __set_value():
    """设置各种值"""
    global all_parsed_args
    if all_parsed_args['debug_enable']:
        all_parsed_args['io'] = process('{}'.format(all_parsed_args['filename']))
    else:
        all_parsed_args['io'] = remote(all_parsed_args['ip'], all_parsed_args['port'])

    if all_parsed_args['tmux_enable'] or all_parsed_args['open_wsl_exe']:
        if all_parsed_args['tmux_enable']:
            context.update(terminal=['tmux', 'splitw', '-h'])
        else:
            # 如果有多个WLS发行版, 注意更改为下方这条设置, 修改ubuntu16, 这是发行版名称
            # context.update(terminal=["open-wsl.exe", "-b", "-d ubuntu16", "-c"])
            context.update(terminal=["open-wsl.exe", "-c"])
        tmp_all_gdb = ""
        if all_parsed_args['gdb_breakpoint'] is not None or len(all_parsed_args['gdb_breakpoint']) > 0:
            # 解析每一条gdb-breakpoint
            for gb in all_parsed_args['gdb_breakpoint']:
                if gb.startswith('0x') or gb.startswith('$rebase('):
                    tmp_all_gdb += "b *{}\n".format(gb) # 带上*
                else: # 传入函数
                    tmp_all_gdb += "b {}\n".format(gb) # 不带*
        if all_parsed_args['gdb_script'] is not None:
            tmp_all_gdb += all_parsed_args['gdb_script'].replace("\\n", "\n").replace(";", "\n") + "\n"
        tmp_all_gdb += "c\n"
        gdb.attach(all_parsed_args['io'], gdbscript=tmp_all_gdb)

    if all_parsed_args['filename']:
        all_parsed_args['cur_elf'] = ELF('{}'.format(all_parsed_args['filename']))
        log.info('[+] libc used ===> {}'.format(all_parsed_args['cur_elf'].libc))

    # 更新context
    context.update(log_level=all_parsed_args['pwn_log_level'])
    # setattr
    for key, val in all_parsed_args.items():
        setattr(all_parsed_args, key, val)

    
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
@click.command(context_settings=CONTEXT_SETTINGS, short_help='Do pwn!')
@click.argument('filename', nargs=1, type=str, required=0, default=None)
@click.option('-d', '--debug', default=True, type=bool, nargs=1, help='Excute program at local env or remote env. Default value: True.')
@click.option('-t', '--tmux', default=False, type=bool, nargs=1, help='Excute program at tmux or not. Default value: False.')
@click.option('-w', '--open-wsl', default=False, type=bool, nargs=1, help='Excute program at open-wsl.exe or not. Default value: False.')
@click.option('-gb', '--gdb-breakpoint', default=[], type=str, multiple=True, help="Set a gdb breakpoint while tmux or 'open-wsl.exe' is enabled, is a hex address or '\$rebase' addr or a function name. Multiple setting supported. Default value:'[]'")
@click.option('-gs', '--gdb-script', default=None, type=str, help="Set a gdb script while tmux or 'open-wsl.exe' is enabled, the script will be passed to gdb and use '\\n' or ';' to split lines. Default value:None")
@click.option('-i', '--ip', default=None, type=str, nargs=1, help='The remote ip addr. Default value: None.')
@click.option('-p', '--port', default=None, type=int, nargs=1, help='The remote port. Default value: None.')
@click.option('-ll', '--local-log', default=True, type=bool, nargs=1, help='Set local log enabled or not. Default value: True.')
@click.option('-pl', '--pwn-log', type=click.Choice(['debug', 'info', 'warn', 'error', 'notset']), nargs=1, default='debug', help='Set pwntools log level. Default value: debug.')
@click.option('-sf', '--stop-function', default=True, type=bool, nargs=1, help='Set stop function enabled or not. Default value: True.')
def __parse_command_args(filename, debug, tmux, open_wsl, gdb_breakpoint, gdb_script,
                         ip, port, local_log, pwn_log, stop_function):
    '''FILENAME: The filename of current directory to pwn'''
    global all_parsed_args
    # 赋值
    all_parsed_args['filename'] = filename
    all_parsed_args['debug_enable'] = debug
    all_parsed_args['tmux_enable'] = tmux
    all_parsed_args['open_wsl_exe'] = open_wsl
    all_parsed_args['gdb_breakpoint'] = gdb_breakpoint
    all_parsed_args['gdb_script'] = gdb_script
    all_parsed_args['ip'] = ip
    all_parsed_args['port'] = port
    all_parsed_args['local_log'] = local_log
    all_parsed_args['pwn_log_level'] = pwn_log
    all_parsed_args['stop_function_enable'] = stop_function

    # change
    __change()
    
    # check
    __check()
    
    # print
    print_parsed_args_info(False, True)


__parse_command_args.main(standalone_mode=False)

# 退出条件，只要参数有 -h 或 --help就退出
if len(sys.argv) > 1:
    for arg in sys.argv:
        if '-h' == arg or '--help' == arg:
            # 打印一下all_parsed_args中所有的键
            click.echo('\n' + '=' * 90)
            click.echo("All keys in 'all_parsed_args': ")
            for key, _ in all_parsed_args.items():
                click.echo("  {}".format(key))
            click.echo('=' * 90)
            sys.exit(0)

__set_value()

# 定义一些函数
def LOG_ADDR(addr_name:str, addr:int):
    """使用log.success打印地址"""
    if all_parsed_args['local_log']:
        log.success("{} ===> {}".format(addr_name, hex(addr)))
    else:
        pass

    
def STOP():
    """程序暂停，按任意键继续"""
    if not all_parsed_args['stop_function_enable']:
        return
    print("stop at line...{} pid:{}".format(sys._getframe().f_lineno, proc.pidof(all_parsed_args['io'])))
    pause()


############### 定义一些偏函数 ###################
int16 = functools.partial(int, base=16)

#################### END ########################



############### 定义一些装饰器函数 ###############
def time_count(func):
    '''
    装饰器：统计函数运行时间
    '''
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        print('=' * 50)
        print('function #{}# start...'.format(func.__name__))
        start = time.time()
        res = func(*args, **kwargs)
        end = time.time()
        print('function #{}# end...execute time: {} s / {} min'.format(func.__name__, end - start, (end - start) / 60))
        return res
    return wrapper


def sleep_call(second:int=1, mod:int=1):
    """
    装饰器：在调用函数前后线程先睡眠指定秒数
    
    Args:
        second: 休眠秒数
        mod: 0 不休眠; 1 为调用前休眠; 2 为调用后休眠; 3 为前后均修眠
    """
    if mod > 3 or mod < 0:
        mod = 1
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            if mod & 1:
                time.sleep(second)
            res = func(*args, **kwargs)
            if mod & 2:
                time.sleep(second)
            return res
        return wrapper2
    return wrapper1

#################### END ########################