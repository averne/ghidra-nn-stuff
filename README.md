# Usage

## Data types archive

- Generate the xml with `make`
  - Needs `castxml` installed
- In Ghidra, run the GhidraCastXML.py script
  - Select the generated xml, and the location to output the symbol archive (.gdt) to
- In the Data types manager, add the .gdt
  - Right click the archive, hit "Apply function data types", which will overwrite function signatures with the new (and fleshed out) types

## Pattern files

- These contains sdk function code as regex patterns, that will be matched against sysmodule binaries
  - These can be generated using [this script](https://github.com/hthh/switch-reversing/blob/master/pattern/makepattern.py) and a sdk NSO (found eg. in the ExeFS partition of a game dump)
- Use the [apply-pattern](scripts/applypattern-ghidra.py) script (`python2 apply-pattern.py <pattern file> <nso>`) to generate a list of symbols present in the binary, and their addresses
  - You can load this data into ghidra using the [apply-syms](scripts/apply-syms.py) script: in ghidra, launch it from the script manager, and select the file you just generated

## IPCserver script

- This script recognizes IPC servicing code and generates a list of symbols for those functions (command dispatching, unpacking and implementation function)
  - Only works on early firmwares (around pre-4.0.0)
  - Use it with `python2 ipcserver_classic-ghidra.py <nso>`, and load the generated file with the apply-syms scripts
