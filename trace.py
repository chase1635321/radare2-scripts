#!/usr/bin/python3

import r2pipe
from termcolor import colored
import os

r = r2pipe.open()

cache = ""
try:
    with open("trace_cache.txt") as f:
        cache = f.read()
except:
    print("No cache found, analyzing now")
    r.cmd("aaa")
    functions = r.cmdj("aflj")

    functionData = []

    for a in functions:
        if a['size'] > 30:
            print("[+] Added breakpoint at function " + colored(a['name'], "green") + " of size " + str(a['size']))

            r.cmd("db " + hex(a['offset']))
            r.cmd("s " + hex(a['offset']))

            for line in r.cmd("pdg").split("\n"):
                if "(" in line and ")" in line and line[0] != " " and not "ram" in line:
                    functionData.append(hex(a['offset']) + " " + line)

    with open("trace_cache.txt", "w") as f:
        f.write("\n".join(functionData))

    os.system("cat trace_cache.txt")
    exit()



r.cmd("aaa;")
#r.cmd("Vp")
i = 0.0
total = 0.0

functions = r.cmdj("aflj")

functionData = []

for a in functions:
    if a['size'] > 30:
        print("[+] Added breakpoint at function " + colored(a['name'], "green") + " of size " + str(a['size']))

        r.cmd("db " + hex(a['offset']))

r.cmd("ood sldkfjsldkfj")
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

    found = False
    for line in r.cmd("pdg").split("\n"):
        if "(" in line and ")" in line and line[0] != " " and not "ram" in line:
            found = True
            #line = " ".join(line.split(" ")[2:])
            print(line)
            log += line + "\n"
    r.cmd("dc")

with open("log.txt", "w") as f:
    f.write(log)

print("_"*80)
print("")
#print(functionData)

os.system("cat log.txt")

# sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"

#for i in range(0, 30):
#    output = r.cmd("dc")
#    print("Output: " + output)

