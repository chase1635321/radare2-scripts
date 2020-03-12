#!/usr/bin/python3

import r2pipe
from termcolor import colored
#import Levenshtein as Leven

r = r2pipe.open()

r.cmd("aa;aac")

for a in r.cmdj('aflj'):
    if a['size'] > 128:
        print("[+] Function " + colored(a['name'], "green") + " of size " + str(a['size']))
    else:
        if not "imp" in a['name']:
            r.cmd("s " + a['name'])
            r.cmd("afn _small_" + a['name'])
        if not "call" in r.cmd("pdfj @ " + a['name']) and not "imp" in a['name']:
            r.cmd("s " + a['name'])
            r.cmd("afn _leaf_" + a['name'])

