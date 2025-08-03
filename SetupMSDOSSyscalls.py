# This identifies system calls in MS-DOS MZ applications and replaces them with stubs.
# @author Matthew Turk
# @category _NEW_
# @keybinding
# @menupath
# @toolbar
# @runtime PyGhidra

import os

# https://github.com/numpy/numpy/issues/14474
os.environ["OPENBLAS_NUM_THREADS"] = "1"

import typing

# if typing.TYPE_CHECKING:
# import ghidra
# from ghidra.ghidra_builtins import currentProgram, popup, createFunction, monitor

# TODO Add User Code Here

# from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
from ghidra.app.cmd.memory import AddUninitializedMemoryBlockCmd

# from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.app.plugin.core.analysis import ConstantPropagationContextEvaluator

# from ghidra.app.script import GhidraScript
# from ghidra.app.services import DataTypeManagerService
# from ghidra.app.util.opinion import ElfLoader
from ghidra.app.util.opinion import MzLoader

# from ghidra.framework import Application
# from ghidra.program.model.address import *
# from ghidra.program.model.data import DataTypeManager
# from ghidra.program.model.lang import BasicCompilerSpec
# from ghidra.program.model.lang import Register
from ghidra.program.model.lang import SpaceNames

from ghidra.program.model.listing import ParameterImpl, VariableStorage, Function

# from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import RefType, SourceType, Reference

# from ghidra.program.util import ContextEvaluator
from ghidra.program.util import SymbolicPropogator

# from ghidra.program.util.SymbolicPropogator import Value
# from ghidra.util import Msg
# from ghidra.util.exception import CancelledException
# from ghidra.util.task import TaskMonitor
# from ghidra import program

import xml.etree.ElementTree as ET

import json
from com.kenai.jffi import CallingConvention

SYSCALL_SPACE_NAME = "msdos_syscall"
SYSCALL_SPACE_LENGTH = 0x1000
MSDOS_CALLOTHER = "syscall"
syscallRegister = "AH"
syscallFileName = "/home/mturk/ghidra_scripts/msdos_syscall_numbers.json"
datatypeArchiveName = "generic_clib"
overrideType = RefType.CALLOTHER_OVERRIDE_CALL
callingConvention = "__regcall"
interrupt_list = (
    0x21,
    # 0x60,
)


def updateSysCalls(callDb):
    # We manually add in all the interrupt 0x60 ones.
    arguments = [
        {"reg": "ax", "out": False},
        {"reg": "bx", "out": False},
        {"reg": "cx", "out": False},
        {"reg": "dx", "out": False},
    ]
    returns = []
    for i in range(0xFF):
        callDb[i] = {
            "name": f"syscall_int60_{i:02d}",
            "int_num": 0x60,
            "register": {"ah": i},
            "arguments": arguments,
            "returns": returns,
        }
    return


def loadSysCalls():
    # This loads the full set of system calls and grabs only the int 21h ones, and it also reorganizes them to be searchable by the value of register ah
    # tree = ET.parse("realmodeintservices.xml")
    rawDb = json.load(open(syscallFileName))
    # updateSysCalls(rawDb)
    sysCalls = {}
    for service in rawDb:
        intcalls = sysCalls.setdefault(service["int_num"], {})
        if service["int_num"] not in interrupt_list:
            continue
        register_info = service.pop("register")
        if "ah" not in register_info:
            continue
        intcalls[register_info["ah"]] = service
        print("Setting %s to %s" % (register_info["ah"], service["name"]))
    print(sysCalls.keys())
    return sysCalls[0x21]


def run():
    if not (
        currentProgram.getExecutableFormat() == MzLoader.MZ_NAME
        and currentProgram.getLanguage().getProcessor().toString() == "x86"
    ):
        print("This script is intended for x86 MS-DOS files.")
        # exit(1)

    syscallSpace = currentProgram.getAddressFactory().getAddressSpace(
        SYSCALL_SPACE_NAME
    )
    if syscallSpace is None:
        print("AddressSpace %s not found, creating..." % SYSCALL_SPACE_NAME)
        if not currentProgram.hasExclusiveAccess():
            popup(
                "Must have exclusive access to "
                + currentProgram.getName()
                + " to run this script."
            )
            exit(1)
        startAddr = (
            currentProgram.getAddressFactory()
            .getAddressSpace(SpaceNames.OTHER_SPACE_NAME)
            .getAddress(0x0)
        )
        cmd = AddUninitializedMemoryBlockCmd(
            SYSCALL_SPACE_NAME,
            None,
            "SetupMSDOSSyscalls",
            startAddr,
            SYSCALL_SPACE_LENGTH,
            True,
            True,
            True,
            False,
            True,
        )
        if not cmd.applyTo(currentProgram):
            popup("Failed to create " + SYSCALL_SPACE_NAME)
            exit(1)
        syscallSpace = currentProgram.getAddressFactory().getAddressSpace(
            SYSCALL_SPACE_NAME
        )
    else:
        print("AddressSpace %s found, continuing..." % syscallSpace)
    funcsToCalls = getSyscallsInFunctions(currentProgram, monitor)
    addressesToSyscalls = resolveConstants(funcsToCalls, currentProgram, monitor)
    if len(addressesToSyscalls) == 0:
        print("No syscalls found")
        return
    syscallNumbersToNames = loadSysCalls()
    print(syscallNumbersToNames.keys())
    for callSite, offset in sorted(addressesToSyscalls.items()):
        print("Checking %s and %02X" % (callSite, offset))
        callTarget = syscallSpace.getAddress(offset)
        callee = currentProgram.getFunctionManager().getFunctionAt(callTarget)
        if offset not in syscallNumbersToNames:
            print("Could not identify ", offset)
            continue
        funcInfo = syscallNumbersToNames[offset]
        if callee is None:
            funcName = funcInfo.get("name", "syscall_%08X" % offset)
            callee = createFunction(callTarget, funcName)
            callee.setCallingConvention(callingConvention)
            # callee.updateFunction()
        callee.setCustomVariableStorage(True)
        convertArgumentsToParameters(
            currentProgram, callee, funcInfo.get("arguments", None)
        )
        # convertReturnValuesToReturns(currentProgram, callee, funcInfo.get("return", None), funcInfo.get("arguments", None))
        ref = currentProgram.getReferenceManager().addMemoryReference(
            callSite,
            callTarget,
            overrideType,
            SourceType.USER_DEFINED,
            Reference.MNEMONIC,
        )
        currentProgram.getReferenceManager().setPrimary(ref, True)


dtypes = {
    1: "byte",
    2: "int",
    3: "RequestSuccess",
    4: "SegmentedCodeAddress",
    5: "PointerModificationResult",
}


def convertArgumentsToParameters(program, function, arguments):
    if arguments is None:
        arguments = []
    print("Processing arguments for %s" % function.getName())
    dtm = program.getDataTypeManager()
    root = dtm.getRootCategory()
    dts = dict((s, dtm.getDataType("%s%s" % (root, dt))) for s, dt in dtypes.items())
    params = []
    # First we figure out the arguments.  Note that sometimes our arguments will be both input and output.
    for i, argument in enumerate(arguments):
        if argument["out"]:
            continue  # Skip these, as we will get them later
        if "seq" in argument:
            regs = [
                program.getLanguage().getRegister(r.upper())
                for r in argument["seq"]
                if not r.upper().endswith("S")
                # Note that we specifically avoid including various segments,
                # especially DS here, but we allow stuff like CX:DX.
            ]
        else:
            # We need to adjust this to figure out the "out" registers as well as the "in" registers
            regs = [program.getLanguage().getRegister(argument["reg"].upper())]
        vs = VariableStorage(program, *regs)
        argument_name = argument.get("name", "arg%02i" % i)
        vtype = argument.get("dtype", None)
        if vtype:
            vtype = dtm.getDataType("%s%s" % (root, vtype))
        else:
            vtype = dts[vs.size()]
        params.append(ParameterImpl(argument_name, vtype, vs, program))
    function.replaceParameters(
        params,
        Function.FunctionUpdateType.CUSTOM_STORAGE,
        True,
        SourceType.USER_DEFINED,
    )


unique_returns = set()


def convertReturnValuesToReturns(program, function, returns, arguments):
    if returns is None:
        returns = []
    if arguments is None:
        arguments = []
    print("Processing returns for %s" % function.getName())
    dtm = program.getDataTypeManager()
    root = dtm.getRootCategory()
    dts = dict((s, dtm.getDataType("%s%s" % (root, dt))) for s, dt in dtypes.items())
    returnStorage = []
    for arg in arguments:
        if arg["out"]:
            if "seq" in arg:
                returnStorage.extend(_ for _ in arg["seq"])
            else:
                returnStorage.append(arg["reg"])
    # So here's what we need to do -- we need to figure out all the unique types of returns that we have.  So let's look at this.
    for rv in returns:
        if rv.get("flag"):
            returnStorage.append("CF")
        else:
            returnStorage.append(rv["reg"])
    regs = [
        program.getLanguage().getRegister(r.decode("ascii").upper())
        for r in returnStorage
    ]
    if len(regs) == 0:
        return
    vs = VariableStorage(program, regs)
    function.setReturn(dts[vs.size()], vs, SourceType.USER_DEFINED)


def getSyscallsInFunctions(program, tMonitor):
    funcsToCalls = {}
    for func in program.getFunctionManager().getFunctionsNoStubs(True):
        tMonitor.checkCanceled()
        print("func: ", func)
        for inst in program.getListing().getInstructions(func.getBody(), True):
            if checkInstruction(inst):
                callSites = funcsToCalls.setdefault(func, [])
                callSites.append(inst.getAddress())
    return funcsToCalls


def resolveConstants(funcsToCalls, program, tMonitor):
    addressesToSyscalls = {}
    syscallReg = program.getLanguage().getRegister(syscallRegister)
    print("funcsToCalls: ", funcsToCalls)
    for func in sorted(funcsToCalls, key=lambda a: str(a)):
        start = func.getEntryPoint()
        eval_ = ConstantPropagationContextEvaluator(tMonitor)
        symEval = SymbolicPropogator(program)
        symEval.flowConstants(start, func.getBody(), eval_, True, tMonitor)
        for callSite in funcsToCalls[func]:
            val = symEval.getRegisterValue(callSite, syscallReg)
            if val is None:
                print("Couldn't resolve value of %s" % syscallReg)
                continue
            print("Resolved syscall (at %s) to 0x%02X" % (callSite, val.getValue()))
            addressesToSyscalls[callSite] = val.getValue()
    return addressesToSyscalls


def checkInstruction(inst):
    retVal = False
    for op in inst.getPcode():
        if op.getOpcode() == PcodeOp.CALLOTHER:
            index = int(op.getInput(0).getOffset())
            retVal = retVal or (
                inst.getProgram().getLanguage().getUserDefinedOpName(index)
                == MSDOS_CALLOTHER
            )
    return retVal


run()
