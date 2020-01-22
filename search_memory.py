#!/usr/bin/python3

import r2pipe
import sys


if len(sys.argv) < 2:
    print("Usage: ./leafs <binary>")

r = r2pipe.open(sys.argv[1], flags=['-d', 'rarun2', 'program=binary', 'stdin="AAA"..."any rarun2 key/value pairs"'])

r.cmd("aaa")

r.cmd("dcu main")

bp_count = 0

functions = r.cmd("aflt | awk '$12<1' | awk '{print $6}'").split("\n")
functions = [i for i in functions if i]

for function in functions:
    bp_count += 1
    print("Adding breakpoint" + str(bp_count), end="\r")
    r.cmd("db " + function)

refs = r.cmd("axq | grep DATA | awk {'print $1'}").split("\n")
refs = []
for ref in refs:
    bp_count += 1
    print("Adding breakpoint " + str(bp_count), end="\r")
    r.cmd("db " + ref)

for i in range(0, 100):
    r.cmd("dc")
    data = r.cmd("px 256 @ rsp-128 | strings")
    print(data)
    if "ffff ffff ffff ffff" in data:
        exit()
