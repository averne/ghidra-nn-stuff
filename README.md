# Usage

- Generate the xml with `make`
  - Needs `castxml` installed
- In Ghidra, run the GhidraCastXML.py script
  - Select the generated xml, and the location to output the symbol archive (.gdt) to
- In the Data types manager, add the .gdt
  - Right click the archive, hit "Apply function data types", which will overwrite function signatures with the new (and fleshed out) types
