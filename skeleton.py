#!/usr/bin/python3

import r2pipe
import sys
import os
from r2lib import *

# Important functions:
#   cmd(<command>), shell()

def main():
    r = setup("antir2", analyze="aa", stdin="randominputhere")
    bypass_ptrace()
    cmd("dcu main")
    #continue_trace() This doesn't work yet
    shell()
    

    cleanup()

main()
