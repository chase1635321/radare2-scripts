#!/usr/bin/python3

import r2pipe
import sys
#import Levenshtein as Leven

if len(sys.argv) < 2:
    print("Usage: ./leafs <binary>")

r = r2pipe.open(sys.argv[1])

r.cmd("aaa")

r.cmd("i~static")

functions = r.cmd("aflt | awk '$12<1' | awk '{print $6}'").split("\n")
functions = [i for i in functions if i]

print("Found " + str(len(functions)) + " leaf functions")

for function in functions:
    print(function)

