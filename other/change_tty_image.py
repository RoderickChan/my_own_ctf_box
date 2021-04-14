# -*- encoding: utf-8 -*-
'''
@File    : change_tty_image.py
@Time    : 2021/04/08 21:00:20
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Change windows-terminal background image automatically
'''

import os
import sys
import functools
import random
import re
import time

# key word to set image
key_word = "\"backgroundImage\""

# help message
help_msg = """
Usage: 
    python change_tty_image.py [settings_path] [picture_directory] [update_frequency] [random]
Function:
    Change windows-terminal background image automatically.
Note:
    settings_path:          [required]
        The absolute path of windows-terminal setting file.
    picture_directory:      [required]
        A absolute directory path fulled with pictures, only support 'png', 'jpg', 'gif'.
    update_frequency:       [required]
        The frequency to update image, should be more than 10, default value is 30, which represents 30min.
    random:                 [optional]
        Select image randomly or not. Default value: False.
Tips:
    1. Use `python` to run this script and output log-info on the screen.
    2. Use `pythonw` to run this script in the background and output nothing, but your can use 'tasklist' and 'taskkill' to stop. 
    3. recommendation command:
        pythonw change_tty_image.py [settings_path] [picture_directory] [update_frequency] [random] > change_image.log
    4. Use `python change_tty_image.py -h` to get help.
"""

def get_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 

def log(msg):
    print("\033[1;32mINFO\033[0m: {}    \033[1;34mTime\033[0m: {}\n".format(msg, get_time()))

# parse args
# check args
args = sys.argv
arg_len = len(args)

# show help
if len(args) > 1 and (args[1] == "-h" or args[1] == "--help"):
    print(help_msg)
    sys.exit(0)

if arg_len < 4 or arg_len > 5:
    print("\033[1;31m[-] Args Error!\033[0m\n")
    print(help_msg)
    sys.exit(-1)

# validate args
settings_path = args[1]
picture_directory = args[2]
update_frequency = args[3]
random_enabled = False
if arg_len == 5:
    random_enabled = bool(args[4])

assert os.path.exists(settings_path), "settings_path doesn't exist."
assert os.path.isfile(settings_path), "settings_path is not a file path."
assert os.path.exists(picture_directory), "picture_directory doesn't exist."
assert os.path.isdir(picture_directory), "picture_directory is not a dir path."

# process settings_path
settings_dir, settings_full_name = os.path.split(settings_path)
settings_name, setting_suffix = os.path.splitext(settings_full_name)
backup_setting_path = os.path.join(settings_dir, settings_name + "_backup" + setting_suffix)
tmp_setting_path = os.path.join(settings_dir, settings_name + "_tmpfile" + setting_suffix)


# process update_frequency
if update_frequency.isdecimal():
    update_frequency = int(update_frequency)
    if update_frequency < 10:
        update_frequency = 30
else:
    update_frequency = 30
log('settings_path: {}'.format(settings_path))
log('backup_setting_path: {}'.format(backup_setting_path))
log('picture_directory: {}'.format(picture_directory))
log('update_frequency: {}'.format(update_frequency))
log('random_enabled: {}'.format(random_enabled))

# get all picture path
all_picture_path = []
support_suffix = ('.jpg', '.png', '.gif')
for r, dl, fl in os.walk(picture_directory,):
    for f in fl:
        is_ok = functools.reduce(lambda a, b : a or b, map(lambda x: f.endswith(x), support_suffix))
        if not is_ok:
            continue
        # check size
        if len(all_picture_path) > 0x1000:
            continue;
        all_picture_path.append(os.path.join(r, f))

assert len(all_picture_path) > 0, 'no pictures appended, check your picture_directory.'

# validate settings_path
flag = False
with open(file=settings_path, mode='r+', encoding='utf-8') as fd:
    for line in fd:
        if line.strip().startswith(key_word):
            flag = True
            break
assert flag, "please initial your windows-terminal settings file first, add {} value at least.".format(key_word)

log('all_picture_path : {}'.format(all_picture_path))

# back up
if not os.path.exists(backup_setting_path):
    cmd = "copy {} {}".format(settings_path, backup_setting_path)
    os.popen(cmd)
    log("execute \"{}\"".format(cmd))

idx = -1

while True:
    if random_enabled:
        idx = random.randint(0, len(all_picture_path) - 1)
    else:
        idx += 1
        idx %= len(all_picture_path)
    
    # replace '\' with '/'
    cur_picture_path = all_picture_path[idx].replace("\\", "/")
    log('cur_picture_path: {}'.format(cur_picture_path))
    with open(file=settings_path, mode='r', encoding='utf-8') as fd_src:
        with open(file=tmp_setting_path, mode='w+', encoding='utf-8') as fd_bck:
            for line in fd_src:
                if not line.strip().startswith(key_word):
                    fd_bck.write(line)
                    continue
                res = re.sub(r"({}\s?:\s?)\".+\",".format(key_word), r'\1"{}",'.format(cur_picture_path), line)
                fd_bck.write(res)
    
    cmd = "copy {} {}".format(tmp_setting_path, settings_path)
    os.popen(cmd)
    log("execute \"{}\"".format(cmd))
    
    cmd = "del {}".format(tmp_setting_path)
    os.popen(cmd)
    log("execute \"{}\"".format(cmd))
    
    # sleep
    log("sleep start...")
    time.sleep(update_frequency * 60)
    log("sleep end...")
    

