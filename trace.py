#!/usr/bin/python3

import r2pipe
from termcolor import colored
import os

r = r2pipe.open()

#os.system("rm trace_cache.txt")

cache = ""
try:
    with open("trace_cache.txt") as f:
        cache = f.read()
except:
    print(colored("No cache found, analyzing now", "red"))
    r.cmd("aaa")
    functions = r.cmdj("aflj")

    functionData = []

    arglist = ""
    for a in functions:
        if a['size'] > 30:
            print("[+] Saving function " + colored(a['name'], "green") + " of size " + str(a['size']))

            r.cmd("db " + hex(a['offset']))
            r.cmd("s " + hex(a['offset']))

            for line in r.cmd("pdg").split("\n"):
                if "(" in line and ")" in line and line[0] != " " and not "ram" in line:
                    arglist += hex(a['offset']) + "," + line.split("(")[1].split(")")[0] + "\n"
                    functionData.append(hex(a['offset']) + ";" + line)

    with open("temp.txt", "w") as f:
        f.write(arglist)

    os.system("""cat temp.txt | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > temp2.txt""")

    with open("temp2.txt", "r") as f:
        arglist = f.read().split("\n")

    argCommands = []
    for line in arglist:
        commands = ""
        addr = line.split(",")[0]
        r.cmd("s " + addr)
        other = line.split(",")[1:]
        argCounter = 1
        for arg in other:
            temp = r.cmd("afvd " + arg.split(" ")[-1].replace("*", ""))
            if "char" in arg and "*" in arg:
                print("FOUND CHAR POINTER, arg number " + str(argCounter))
                temp = "ps 1 @ " + temp.split(" ")[-1]
            if len(temp) > 1:
                commands += ";" + temp.strip()
            argCounter += 1
        if commands == "":
            commands = "\n"

        argCommands.append(commands)
    #print(str(argCommands))
    
    finalCache = []
    for i in range(0, len(functionData)):
        #finalCache.append(functionData[i] + argCommands[i].strip()) 
        finalCache.append(functionData[i]) # Could append the commands to run here

    with open("trace_cache.txt", "w") as f:
        f.write("\n".join(finalCache))

    #os.system("cat trace_cache.txt")
    os.system("rm temp.txt; rm temp2.txt")
    print(colored("\nCache generated, run script again to trace program execution", "green"))
    exit()

names = []
breakpoints = []
cache = []
argCommands = {}

with open("trace_cache.txt", "r") as f:
    cache = f.read().split("\n")


baddrDiff = 0
baddr1 = int(r.cmd("e~baddr").split(" ")[2], 16)
r.cmd("ood sldkfjsldkfj")
baddr2 = int(r.cmd("e~baddr").split(" ")[2], 16)

baddrDiff = baddr2-baddr1

for line in cache:
    b = line.split(";")[0]
    n = line.split(";")[1]
    print("[+] Added breakpoint at function " + n)
    breakpoints.append(b)
    names.append(n)
    if not "void" in str(line.split(";")[2:]):
        argCommands[int(b, 16)] = line.split(";")[2:]
    else:
        argCommands[int(b, 16)] = []

    r.cmd("db " + hex(int(b, 16) + baddrDiff))

# Code was here

print(colored("Static base address: " + hex(baddr1), "yellow"))
print(colored("Process base address: " + hex(baddr2), "yellow"))

output = "hit"

last1 = "a"
last2 = "b"
last3 = "c"
last4 = "d"

hits = []

print(str(argCommands))

log = ""
while True:
    last4 = last3
    last3 = last2
    last2 = last1
    last1 = r.cmd("dr rip")

    if last1 == last3 and last2 == last4 and last1 != last2:
        break

    try:
        #print(str(int(r.cmd("dr rip").strip(), 16)))
        for c in argCommands[int(r.cmd("dr rip").strip(), 16)]:
            print(c)
    except:
        pass

    hits.append(r.cmd("dr rip").strip())
    r.cmd("dc")

print(hits)
for hit in hits:
    for line in cache:
        if int(line.split(";")[0].strip(), 16) == int(hit.strip(), 16)-baddrDiff:
            temp = ";".join(line.split(";")[1:]) + "\n"
            log += temp

with open("log.txt", "w") as f:
    f.write(log)

print("_"*80)
print("")

os.system("cat log.txt")

# sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"

