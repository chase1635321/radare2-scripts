#!/usr/bin/python3

import r2pipe
import sys
import os

def cmd(command):
    global r
    print(r.cmd(command))

def shell():
    while True:
        print("[", end='')
        print(r.cmd("pd 1 ~0x | awk {'print $1'}").strip(), end='')
        print("]> ", end='')

        cmd = input()
        if cmd == "q":
            return
        elif cmd == "clear":
            os.system("clear")
        else:
            print(r.cmd(cmd))

def setup(binary, analyze="", stdin=""):
    global r
    os.system("clear")
    with open("profile.rr2", "w+") as f:
        f.write('#!/usr/bin/rarun2\nstdin=\"' + stdin + '\"')
    
    r = r2pipe.open(filename=binary)
    print("Analyzing binary...")

    r.cmd(analyze)

    r.cmd("e dbg.profile=profile.rr2")
    
    r.cmd("ood")

    return r

# THIS DOESN'T WORK YET
def continue_trace():
    global r
    
    functions = get_functions()
    print(functions)

def get_functions():
    functions = r.cmd("aflt | awk '$12<1' | awk '{print $6}'").split("\n")
    functions = [i for i in functions if i]
    return functions

def banner(s):
    print("="*20 + " " + s + " " + "="*20)

def bypass_ptrace():
    global r
    
    banner("Bypassing ptrace")

    r.cmd("dcs ptrace")
    r.cmd("ds 7")
    r.cmd("dr rax = 0")
    r.cmd("ds 1")

    banner("Done")
    print("")
    os.system("clear")
    print("Bypassed ptrace...")
    

def cleanup():
    os.system("rm profile.rr2")

r = ''

