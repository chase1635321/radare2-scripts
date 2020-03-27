#!/usr/bin/python3

import r2pipe
from termcolor import colored
import os
#import Levenshtein as Leven

# Option to rename functions
# Can see dissasembly or summary
# Progress bar at the top

r = r2pipe.open()

r.cmd("ood;aa;aac")
#r.cmd("Vp")
i = 0.0
total = 0.0

functions = r.cmdj("aflj")

for a in functions:
    if a['size'] > 30:
        print("[+] Added breakpoint at function " + colored(a['name'], "green") + " of size " + str(a['size']))
        #r.cmd("s " + a['name'])
        #print("b " + hex(a['offset']))
        r.cmd("db " + hex(a['offset']))
        #r.cmd("dbc " + hex(a['offset']) + " dc")

#r.cmd("dc")

output = "hit"

last1 = "a"
last2 = "b"
last3 = "c"
last4 = "d"

log = ""
while True:
    last4 = last3
    last3 = last2
    last2 = last1
    last1 = r.cmd("dr rip")

    if last1 == last3 and last2 == last4 and last1 != last2:
        break

    for line in r.cmd("pd 1").split("\n"):
        if "(" in line and ")" in line and ";" in line:
            line = " ".join(line.split(" ")[2:])
            print(line)
            log += line + "\n"
    r.cmd("dc")

with open("log.txt", "w") as f:
    f.write(log)

print("_"*80)
print("")

os.system("cat log.txt")

#for i in range(0, 30):
#    output = r.cmd("dc")
#    print("Output: " + output)
