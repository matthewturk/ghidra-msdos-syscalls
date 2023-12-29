# Based on https://gist.github.com/carlreinke/3096fc7cf310a2277b47702eb4c93524

import typing
from ghidra.program.util import OperandFieldLocation
from ghidra.program.model.listing import Listing, Data, Instruction
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.model.lang import OperandType
from ghidra.program.model.scalar import Scalar
from ghidra.program.database import ProgramDB
from ghidra.app.script import GhidraScript

if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import currentLocation, currentProgram


def run():
    loc = currentLocation()
    if not isinstance(loc, OperandFieldLocation):
        print("Not an operand!")
        return
    addr: Address = loc.getAddress()
    program: ProgramDB = currentProgram()
    listing: Listing = program.getListing()
    inst: Instruction = listing.getInstructionAt(addr)
    operand_index = loc.getOperandIndex()
    suboperand_index = loc.getSubOperandIndex()
    suboperand: Scalar = inst.getDefaultOperandRepresentationList(operand_index)[
        suboperand_index
    ]
    if not isinstance(suboperand, Scalar):
        print("Not a scalar")
        return
    newAddr: Address = program.parseAddress(
        f"{0x235b:04X}:{suboperand.getValue(0):04X}", False
    )[0]
    print(newAddr)
    inst.addOperandReference(
        operand_index, newAddr, RefType.DATA, SourceType.USER_DEFINED
    )
    return
    program.getReferenceManager().addMemoryReference(loc.getByteAddress())

    print(loc, addr)
    print(addr)
    return
    data: Data = listing.getDataContaining(addr)
    if data is None:
        print("No data at location.", data)
        return
    componentPath = loc.getComponentPath()
    data: Data = data.getComponent(componentPath)
    if data.isPointer() and data.getLength() == 4:
        bytes = data.getBytes()
        offset = ((bytes[1] & 0xFF) << 8) | (bytes[0] & 0xFF)
        segment = ((bytes[3] & 0xFF) << 8) | (bytes[2] & 0xFF)
        bad_target = program.parseAddress(f"{offset:04X}:{segment:04X}")
        target = program.parseAddress(f"{offset:04X}:{segment:04X}")
        data.removeValueReference(bad_target)
        data.addValueReference(target)
    else:
        print("Not a far pointer at location.")


run()
