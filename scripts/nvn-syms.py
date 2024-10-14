from ghidra.program.model.data import *
from ghidra.program.model.symbol import *

func_mgr = currentProgram.getFunctionManager()

str_addr  = askAddress("String table address", "")
fptr_addr = askAddress("Function table address", "")

string = getDataAt(str_addr)
while string is not None:
    name = "nvn" + string.value
    func_addr = getDataAt(fptr_addr).value
    func = func_mgr.getFunctionContaining(func_addr)
    if func is not None:
        func.setName(name, SourceType.ANALYSIS)
    else:
        createFunction(func_addr, name)

    print("Renamed " + "nvn" + string.value)

    str_addr  = toAddr(str_addr.offset + string.length)
    fptr_addr = toAddr(fptr_addr.offset + 8)

    string = getDataAt(str_addr)
