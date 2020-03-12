#!/usr/bin/python3

import r2pipe
from termcolor import colored
import os
#import Levenshtein as Leven

# Option to rename functions
# Can see dissasembly or summary
# Progress bar at the top

r = r2pipe.open()

r.cmd("aa;aac")
#r.cmd("Vp")
i = 0.0
total = 0.0
for a in r.cmdj('aflj'):
    if a['size'] > 128 and not "leaf" in a['name']:
        total += 1.0

for a in r.cmdj('aflj'):
    if a['size'] > 128 and not "leaf" in a['name']:
        os.system("clear")
        i += 1
        
        print("[" + "="*int(80*i/total) + ">" + " "*int(80*(1-i/total)) + "]")
        print("[+] Function " + colored(a['name'], "green") + " of size " + str(a['size']))
        r.cmd("s " + a['name'])
        #if len(r.cmd("pdf").split("\n")) > 50:
        #    print(r.cmd("pd 50"))
        #else:
        #    print(r.cmd("pdf"))
        data = r.cmd("pdi")
        for line in data.split("\n"):
            if "call" in line:
                print(line)
        print("...")
        print("Help: ")
        print(" >> ", end='')
        user_input = input()
        if user_input.strip() == "q":
            exit()
        elif not user_input.strip() == "":
            r.cmd("afn " + user_input.strip())
