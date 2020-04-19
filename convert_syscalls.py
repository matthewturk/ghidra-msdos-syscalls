from pathlib import Path
from typing import Tuple, Dict
import json
syscalls = []

# Now let's parse our XML from reko https://github.com/uxmal/reko
import xml.etree.ElementTree as ET
tree = ET.parse('realmodeintservices.xml')
library = tree.getroot()

interrupts = {}

# Under syscallinfo we can have a vector and multiple regvalues, which each are
# associated with a register name

# So our JSON structure will be a list of services, each of which will have
# regvalues and vectors, and then inside their signature attribute will be the
# signature for the registers.

for service in library:
    # There should only be one vector per service
    syscallinfo = service.find('syscallinfo')
    int_num = int(syscallinfo.find('vector').text, 16)
    syscall = {}
    syscall['name'] = service.get('name')
    syscall['int_num'] = int_num
    syscall['register'] = {reg.get('reg'): int(reg.text, 16)
                           for reg in syscallinfo.findall("regvalue")}
    sig = service.find("signature")
    arguments = syscall['arguments'] = []
    for arg in sig.findall("arg"):
        is_out = arg.get('out', "false").capitalize()
        is_out = {'False': False, 'True': True}[is_out]
        if len(arg.findall("seq")) == 1:
            assert(len(arg.findall("reg")) == 0)
            # We have a sequence of registers that get concatenated together
            for reg in arg.find("seq").findall("reg"):
                register_name = reg.text
            arguments.append( {'seq': [_.text for _ in arg.find("seq").findall("reg")],
                               'out': is_out} )
        elif len(arg.findall("reg")) == 1:
            register_name = arg.find("reg").text
            arguments.append( {'reg': register_name, 'out': is_out} )
        else:
            assert(len(arg.findall("reg")) == 0)
        if arg.get("name", None) is not None:
            arguments[-1]['name'] = arg.get("name")
    return_info = syscall['return'] = []
    r = sig.find("return")
    if r is not None:
        return_info.extend( [{'flag': _.text} for _ in r.findall("flag")] )
        return_info.extend( [{'reg': _.text} for _ in r.findall("reg")] )
    syscalls.append(syscall)

json.dump(syscalls, open("msdos_syscall_numbers.json", "w"), indent = 2)

