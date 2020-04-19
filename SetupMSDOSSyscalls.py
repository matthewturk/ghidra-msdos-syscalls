#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
from ghidra.app.cmd.memory import AddUninitializedMemoryBlockCmd
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.app.plugin.core.analysis import ConstantPropagationContextEvaluator
from ghidra.app.script import GhidraScript
from ghidra.app.services import DataTypeManagerService
from ghidra.app.util.opinion import ElfLoader
from ghidra.app.util.opinion import MzLoader
from ghidra.framework import Application
from ghidra.program.model.address import *
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.lang import BasicCompilerSpec
from ghidra.program.model.lang import Register
from ghidra.program.model.listing import Variable, ParameterImpl, VariableStorage
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import RefType, SourceType, Reference
from ghidra.program.util import ContextEvaluator
from ghidra.program.util import SymbolicPropogator
from ghidra.program.util.SymbolicPropogator import Value
from ghidra.util import Msg
from ghidra.util.exception import CancelledException
from ghidra.util.task import TaskMonitor
from ghidra import program

import json
from com.kenai.jffi import CallingConvention

SYSCALL_SPACE_NAME = "msdos_syscall"
SYSCALL_SPACE_LENGTH = 0x1000
MSDOS_CALLOTHER = "syscall"
syscallRegister = "AH"
syscallFileName = "msdos_syscall_numbers.json"
datatypeArchiveName = "generic_clib"
overrideType = RefType.CALLOTHER_OVERRIDE_CALL
callingConvention = "__regcall"

def run():
    if not (currentProgram.getExecutableFormat() == MzLoader.MZ_NAME and \
            currentProgram.getLanguage().getProcessor().toString() == "x86"):
        print "This script is intended for x86 MS-DOS files."
        exit(1)
        
    syscallSpace = currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME)
    if syscallSpace is None:
        print("AddressSpace %s not found, creating..." % SYSCALL_SPACE_NAME)
        if not currentProgram.hasExclusiveAccess():
            popup("Must have exclusive access to " + currentProgram.getName() + " to run this script.")
            exit(1)
        startAddr = currentProgram.getAddressFactory().getAddressSpace(
            BasicCompilerSpec.OTHER_SPACE_NAME).getAddress(0x0)
        cmd = AddUninitializedMemoryBlockCmd(SYSCALL_SPACE_NAME, None, "SetupMSDOSSyscalls",
                                             startAddr, SYSCALL_SPACE_LENGTH, True, True, True, False, True)
        if not cmd.applyTo(currentProgram):
            popup("Failed to create " + SYSCALL_SPACE_NAME)
            exit(1)
        syscallSpace = currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME)
    else:
        print("AddressSpace %s found, continuing..." % syscallSpace)
    funcsToCalls = getSyscallsInFunctions(currentProgram, monitor)
    addressesToSyscalls = resolveConstants(funcsToCalls, currentProgram, monitor)
    if len(addressesToSyscalls) == 0:
        print "No syscalls found"
        return
    import os
    print(os.getcwd())
    syscallNumbersToNames = json.load(open(syscallFileName))
    for callSite, offset in sorted(addressesToSyscalls.items()):
        callTarget = syscallSpace.getAddress(offset)
        callee = currentProgram.getFunctionManager().getFunctionAt(callTarget)
        funcInfo = syscallNumbersToNames[str(offset)]
        if callee is None:
            funcName = "msdos_" + funcInfo.get("name", "syscall_%08X" % offset)
            callee = createFunction(callTarget, funcName)
            callee.setCallingConvention(callingConvention)
            callee.updateFunction(None, None, )
        callee.setCustomVariableStorage(True)
        convertArgumentsToParameters(currentProgram, callee, funcInfo.get("arguments", []))
        print(type(callee))
        ref = currentProgram.getReferenceManager().addMemoryReference(
            callSite, callTarget, overrideType, SourceType.USER_DEFINED, Reference.MNEMONIC)
        currentProgram.getReferenceManager().setPrimary(ref, True)

dtypes = {1: "byte", 2: "int", 4: "SegmentedCodeAddress"}

def convertArgumentsToParameters(program, function, arguments):
    print("Processing %s" % function.getName())
    dtm = program.getDataTypeManager()
    root = dtm.getRootCategory()
    dts = dict( (s, dtm.getDataType("%s%s" % (root, dt)))
                for s, dt in dtypes.items() )
    params = []
    for i, argument in enumerate(arguments):
        # We need to adjust this to figure out the "out" registers as well as the "in" registers
        regs = [program.getLanguage().getRegister(
            reg['register'].decode('ascii').upper())
                for reg in argument]
        vs = VariableStorage(program, regs)
        params.append(ParameterImpl("arg%02i" % i, dts[vs.size()], vs, program))
    function.replaceParameters(params, function.FunctionUpdateType.CUSTOM_STORAGE,
                               True, SourceType.USER_DEFINED)

def getSyscallsInFunctions(program, tMonitor):
    funcsToCalls = {}
    for func in program.getFunctionManager().getFunctionsNoStubs(True):
        tMonitor.checkCanceled()
        for inst in program.getListing().getInstructions(func.getBody(), True):
            if checkInstruction(inst):
                callSites = funcsToCalls.setdefault(func, [])
                callSites.append(inst.getAddress())
    return funcsToCalls

def resolveConstants(funcsToCalls, program, tMonitor):
    addressesToSyscalls = {}
    syscallReg = program.getLanguage().getRegister(syscallRegister)
    for func in sorted(funcsToCalls, key = lambda a: str(a)):
        start = func.getEntryPoint()
        eval_ = ConstantPropagationContextEvaluator(True)
        symEval = SymbolicPropogator(program)
        symEval.flowConstants(start, func.getBody(), eval_, True, tMonitor)
        for callSite in funcsToCalls[func]:
            val = symEval.getRegisterValue(callSite, syscallReg)
            if val is None:
                print "Couldn't resolve value of %s" % syscallReg
                continue
            print "Resolved syscall to 0x%02X" % val.getValue()
            addressesToSyscalls[callSite] = val.getValue()
    return addressesToSyscalls

def checkInstruction(inst):
    retVal = False
    for op in inst.getPcode():
        if op.getOpcode() == PcodeOp.CALLOTHER:
            index = op.getInput(0).getOffset()
            retVal = retVal or (
                inst.getProgram().getLanguage().getUserDefinedOpName(index) == MSDOS_CALLOTHER)
    return retVal

run()
