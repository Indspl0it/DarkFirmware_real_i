#Override flow of the last instruction in functions
#@author Veronica Kovah - Copyright 2025 Dark Mentor LLC - https://darkmentor.com
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

import ghidra.program.model.listing.FlowOverride as FlowOverride

START_ADDR = 0x80000000      # inclusive
END_ADDR   = 0x80100000      # exclusive


def fixEpilogue(func):
    if func is None:
        return

    entryPoint = func.getEntryPoint()
    endAddr = func.getBody().getMaxAddress()  # odd numbered address

    # last instruction e.g. _addiu sp,0x18
    tmpInst = listing.getInstructionBefore(endAddr)
    instStr = tmpInst.toString()
    if "add" in instStr and "sp" in instStr:
        print endAddr
        
        # one insturction before the last e.g. jr a3
        jumpInst = tmpInst.getPrevious()
        jumpInst.setFlowOverride(FlowOverride.RETURN)


# Get the current program
currentProgram = getCurrentProgram()
listing = currentProgram.getListing()
monitor = getMonitor()

startAddr = currentAddress.getNewAddress(START_ADDR)
endAddr = currentAddress.getNewAddress(END_ADDR)

tmpAddr = startAddr
tmpFunc = getFunctionAt(startAddr)

while tmpAddr < endAddr:
    fixEpilogue(tmpFunc)
    
    tmpFunc = getFunctionAfter(tmpAddr)
    if tmpFunc is None:
        break

    tmpAddr = tmpFunc.getEntryPoint()
