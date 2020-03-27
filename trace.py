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
    print(colored("No cache found, analyzing now", "red"))
    r.cmd("aaa")
    functions = r.cmdj("aflj")

    functionData = []

    for a in functions:
        if a['size'] > 30:
            print("[+] Saving function " + colored(a['name'], "green") + " of size " + str(a['size']))

            r.cmd("db " + hex(a['offset']))
            r.cmd("s " + hex(a['offset']))

            for line in r.cmd("pdg").split("\n"):
                if "(" in line and ")" in line and line[0] != " " and not "ram" in line:
                    functionData.append(hex(a['offset']) + ";" + line)

    with open("trace_cache.txt", "w") as f:
        f.write("\n".join(functionData))

    os.system("cat trace_cache.txt")
    print(colored("\nCache generated, run script again to trace program execution", "green"))
    exit()

names = []
breakpoints = []
cache = []

with open("trace_cache.txt", "r") as f:
    cache = f.read().split("\n")

for line in cache:
    b = line.split(";")[0]
    n = line.split(";")[1]
    print("[+] Added breakpoint at function " + n)
    breakpoints.append(b)
    names.append(n)

    r.cmd("db " + b)

baddr1 = int(r.cmd("e~baddr").split(" ")[2], 16)
r.cmd("ood sldkfjsldkfj")
baddr2 = int(r.cmd("e~baddr").split(" ")[2], 16)

print(colored("Static base address: " + hex(baddr1), "yellow"))
print(colored("Process base address: " + hex(baddr2), "yellow"))

output = "hit"

last1 = "a"
last2 = "b"
last3 = "c"
last4 = "d"

hits = []

log = ""
while True:
    last4 = last3
    last3 = last2
    last2 = last1
    last1 = r.cmd("dr rip")

    if last1 == last3 and last2 == last4 and last1 != last2:
        break

    hits.append(r.cmd("dr rip").strip())
    r.cmd("dc")

print(hits)
for hit in hits:
    for line in cache:
        if int(line.split(";")[0].strip(), 16) == int(hit.strip(), 16):
            log += line.split(";")[1] + "\n"

with open("log.txt", "w") as f:
    f.write(log)

print("_"*80)
print("")

os.system("cat log.txt")

# sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"

