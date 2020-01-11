from z3 import *
x = Int('x')
y = Int('y')
z = Int('z')
m = Int('m')
solve(x>=0,y>=0,z>=0,m>=0,199*x+299*y+399*z+499*m==7174)

