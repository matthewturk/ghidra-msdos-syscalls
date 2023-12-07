import xml.etree.ElementTree as ET
import json

tree = ET.parse("realmodeintservices.xml")
root = tree.getroot()

services = {}


def process_prim(arg, suffix=""):
    if (prim := arg.find("prim")) is not None:
        rv = {
            "type": f"{prim.attrib.get('domain', 'undefined')}{suffix}",
        }
        if "size" in prim.attrib:
            rv["size"] = prim.attrib["size"]
        return rv
    elif ptr := arg.find("ptr"):
        return process_prim(ptr, "*")
    elif segptr := arg.find("segptr"):
        return process_prim(segptr, "*")
    return {}


def process_arg(arg, argi):
    thisarg = {"name": arg.attrib.get("name", f"param_{argi}")}
    thisarg.update(process_prim(arg))
    if seq := arg.find("seq"):
        # This indicates that we have multiple registers in a single
        # argument
        thisarg["storage"] = [reg.text for reg in seq.findall("reg")]
    elif reg := arg.findall("reg"):
        assert len(reg) == 1
        thisarg["storage"] = reg[0].text.strip()
    elif flag := arg.findall("flag"):
        assert len(flag) == 1
        thisarg["storage"] = flag[0].text.strip()
    return thisarg


for service in root:
    if service.tag != "service":
        continue
    name = service.attrib["name"]
    syscall = service.find("syscallinfo")
    signature = service.find("signature")
    vector = int(syscall.find("vector").text or "1", base=16)
    registers = {}
    for register in syscall.findall("regvalue"):
        registers[register.attrib["reg"]] = int(register.text, base=16)
    sig = {"return": [], "args": []}
    services[name] = {"vector": vector, "registers": registers, "signature": sig}
    for argi, arg in enumerate(signature.findall("arg")):
        # Each arg
        thisarg = process_arg(arg, argi)
        sig["args"].append(thisarg)
        if arg.attrib.get("out", False):
            # In this case, we will need to handle it during our return value
            # work.  So, we have it here, but *also* in our retvals.
            # Note that the name doesn't really matter that much here I think.
            # We'll have to update the struct names manually I think.
            sig["return"].append(thisarg)
    for argi, arg in enumerate(signature.findall("return")):
        sig["return"].append(process_arg(arg, argi))

json.dump(services, open("msdos_syscalls.json", "w"), indent=2)
