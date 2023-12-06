import xml.etree.ElementTree as ET

tree = ET.parse("realmodeintservices.xml")
root = tree.getroot()

services = {}


def process_prim(arg):
    if (prim := arg.find("prim")) is not None:
        return dict(prim.attrib)
    elif ptr := arg.find("ptr"):
        return process_prim(ptr)
    elif segptr := arg.find("segptr"):
        return process_prim(segptr)
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
    retvals = signature.findall("return")
    for argi, arg in enumerate(signature.findall("arg")):
        # Each arg
        thisarg = process_arg(arg, argi)
        sig["args"].append(thisarg)
        if arg.attrib.get("out", False):
            # In this case, we will need to handle it during our return value
            # work.  So, we have it here, but *also* in our retvals.
            retvals.append(sig["args"][-1])
    for argi, arg in enumerate(signature.findall("return")):
        sig["return"].append(process_arg(arg, argi))
