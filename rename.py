#!/usr/bin/python3

import r2pipe
#import Levenshtein as Leven

r = r2pipe.open()

r.cmd("aa;aac")

for a in r.cmdj('aflj'):
    if a['size'] > 128:
        print("[+] Function " + a['name'] + " of size " + str(a['size']))
    else:
        if not "imp" in a['name']:
            r.cmd("s " + a['name'])
            r.cmd("afn small_" + a['name'])
        elif not "call" in r.cmd("pdfj @ " + a['name']):
            r.cmd("s " + a['name'])
            r.cmd("afn leaf_" + a['name'])

