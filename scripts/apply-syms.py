from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.label import DemanglerCmd

class FunctionIterator():
    cur_func = getFirstFunction()

    def __iter__(self):
        return self

    def next(self):
        self.cur_func = getFunctionAfter(self.cur_func)
        if self.cur_func is None:
            raise StopIteration
        return self.cur_func


def set_demangled_name(addr, name):
    cmd = DemanglerCmd(addr, name)
    return cmd.applyTo(currentProgram, monitor), cmd.getResult()


f = askFile("Select symbols file", "Ok")
fp = open(f.absolutePath)
syms = [line.split() for line in fp]

failed = []
for i, (addr, name) in enumerate(syms):
    addr = toAddr(addr)

    f = getFunctionAt(addr)
    if f is None:
        f = createFunction(addr, name)
    if f is None:
        failed.append((addr, name))

    res, demangled = set_demangled_name(addr, name)
    if demangled is None:                       # Demangle failed, likely because the name was not mangled
        f.setName(name, SourceType.ANALYSIS)    # Fall back to the original name
        demangled = name

    if res:
        print("[%d/%d] Applied symbol at %s (%s)" % (i + 1, len(syms), addr, demangled))
    else:
        failed.append((addr, name))

# Created functions will not get renamed to their demangled symbol
# Forcefully set it
for func in FunctionIterator():
    name, addr = str(func), func.getEntryPoint()
    if (name.startswith("_Z")):
        removeSymbol(addr, name)
        res, demangled = set_demangled_name(addr, name)
        if res:
            print("Forcefully demangled symbol at %s (%s)" % (addr, demangled))
        else:
            failed.append((addr, name))

for addr, name in failed:
    print("FAILED to apply symbol at %s (%s)" % (addr, name))
