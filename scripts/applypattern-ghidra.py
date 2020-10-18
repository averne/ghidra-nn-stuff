#!/bin/python2

import os, sys
import re
import lib.nxo64 as nxo64

def main(pattern, filename):
    f = nxo64.load_nxo(open(filename, 'rb'))

    f.binfile.seek(0)
    target_text = f.binfile.read(f.textsize)

    rows = eval('[' + open(pattern).read() + ']')

    path = os.path.join(os.path.dirname(filename), os.path.basename(filename) + '-sdk-syms.txt')
    with open(path, "wb") as f:

        for value, size, regex, name in rows:
            #print '(0x%X, 0x%X, %r, %r),' % (sym.value, sym.size, regex, sym.name)
            positions = [m.start() for m in re.finditer(regex, target_text)]
            if len(positions) == 1:
                f.write('%#x %s\n' % (0x7100000000 + positions[0], name))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'usage: applypattern.py pattern.txt [nxo files...]'
        print 'writes output to input filename + "-sdk-syms.txt"'
    for filename in sys.argv[2:]:
        main(sys.argv[1], filename)
