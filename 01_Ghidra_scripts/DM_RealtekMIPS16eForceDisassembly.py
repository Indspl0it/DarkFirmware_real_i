#Simply disassemble undefined binary (Realtek RTL8761B chips)
#@author Veronica Kovah - Copyright 2025 Dark Mentor LLC - https://darkmentor.com
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

import time

from ghidra.app.cmd.disassemble import MipsDisassembleCommand
from ghidra.program.model.address import AddressSet

START_ADDR = 0x00000030     # inclusive
END_ADDR = 0x0000adc4       # exclusive

# Get the current program
currentProgram = getCurrentProgram()
listing = currentProgram.getListing()
monitor = getMonitor()

def disassembleAt(startAddr):

    # Create the MipsDisassembleCommand
    # The third argument 'True' enables MIPS16e mode
    disassemble_command = MipsDisassembleCommand(startAddr, None, True)

    # Execute the command
    if disassemble_command.applyTo(currentProgram, monitor):
        # nop was not disassembled with other instructions at the end of functions                
        inst = getInstructionAt(startAddr)
        if inst and inst.getMnemonicString() == "nop":
            return

        print(startAddr)
        createFunction(startAddr, None)
        time.sleep(0.3)     # give Ghidra some time to analyze the program to recognize data

startAddr = currentAddress.getNewAddress(START_ADDR)
endAddr = currentAddress.getNewAddress(END_ADDR)

undefined = None

tmpAddr = startAddr
while tmpAddr < endAddr:
    disassembleAt(tmpAddr)

    undefined = getUndefinedDataAfter(tmpAddr)
    if undefined is None:
        break
    tmpAddr = undefined.getAddress()

