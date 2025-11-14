#Define struct pointer types
#@author Veronica Kovah - Copyright 2025 Dark Mentor LLC - https://darkmentor.com
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.data import Pointer
from ghidra.program.model.data import PointerDataType

START_ADDR = 0x80000000      # inclusive
END_ADDR   = 0x80100000      # exclusive

structOne = [0x8012dc50, "big_ol_struct"]
structTwo = [0x801259ec, "the_0x300"]

STRUCT_INFO = [structOne, structTwo] 

# Get the current program
currentProgram = getCurrentProgram()
listing = currentProgram.getListing()

def defineStructPtr(data):
    if data is None:
        return

    dataAddr = data.getAddress()

    if isinstance(data.getDataType(), Pointer) and data.getValue() in addrArray:
        clearListing(dataAddr, dataAddr.add(3))

        idx = addrArray.index(data.getValue())
        ret = createData(dataAddr, structArray[idx][1])
        if ret is None:
            print "ERROR: failed to make a struct pointer"

        print "%s %s" % (dataAddr.toString(), STRUCT_INFO[idx][1])


startAddr = currentAddress.getNewAddress(START_ADDR)
endAddr = currentAddress.getNewAddress(END_ADDR)

dtm = currentProgram.getDataTypeManager()
structArray = []
addrArray = []

for structInfo in STRUCT_INFO:
    tmpStructAddr = currentAddress.getNewAddress(structInfo[0]) 
    tmpStructData = dtm.getDataType("/%s" % structInfo[1]) 

    if tmpStructData is None:
        print "ERROR: Check the struct name %s" % tmpPtr
        exit()

    tmpStructPtr = PointerDataType(tmpStructData)

    tmpStructArray = [tmpStructAddr, tmpStructPtr]
    structArray.append(tmpStructArray)
    addrArray.append(tmpStructAddr)


tmpAddr = startAddr
tmpData = getDataAt(tmpAddr)

while tmpAddr < endAddr:
    defineStructPtr(tmpData)
    
    tmpData = getDataAfter(tmpAddr)
    if tmpData is None:
        break

    tmpAddr = tmpData.getAddress()
