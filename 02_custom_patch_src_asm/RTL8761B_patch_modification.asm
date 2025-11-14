# Xeno Kovah - Dark Mentor LLC - https://darkmentor.com
# Copyright (c) Dark Mentor LLC 2025
# PoC code to patch Realtek RTL8761B firmware
# Assembled bytes to be extracted and used with _RTL8761B_USB_Windows_usbbluetooth_Patch_Download* python script
# Compile with: mipsel-linux-gnu-as -mips32r2 -mips16 -o RTL8761B_patch_modification.o RTL8761B_patch_modification.asm
# Disassemble with: mipsel-linux-gnu-objdump -mips16 -EL -d RTL8761B_patch_modification.o
# Extract bytes with: python3 ./print_hex_bytes.py

# IMPORTANT NOTE TO SELF!: JALRC DOESN'T WORK! (Even though jrc does!)

        .set    noreorder
        .set    mips16
        .text
        .global _start_install_fptrs

# Reached via first-function-in-patches inline prolog hook
_start_install_fptrs:
	# HCI CMD hook
.align 2				# If I don't add these, it seems to not keep from generating invalid lw
        lw      $v1, patch_target_1	# Load up the location where to read/write fptr for HCI CMD hook
	lw	$a0, 0($v1)		# Dereference the address, to get the existing pointer (should be 0x80014181)
.align 2
	lw	$v0, backup_addr_1	# Load up the backup location
        sw      $a0, 0($v0)		# Store original fptr to backup, to call into original later
.align 2
	la      $v0, _installed_fptr_1	# Get the address we want to use to replace the previous fptr (pseudo-instruction)
	sw	$v0, 0($v1)		# Write our fptr so it gets called in all HCI CMD control flow

	# LMP hook
.align 2				# If I don't add these, it seems to not keep from generating invalid lw
        lw      $v1, patch_target_2	# Load up the location where to read/write fptr for LMP hook
	lw	$a0, 0($v1)		# Dereference the address, to get the existing pointer (should be 0x8010dfb1 for the 0xd922 patch, for USB/RTL8761BUV chip)
.align 2
	lw	$v0, backup_addr_2	# Load up the backup location
        sw      $a0, 0($v0)		# Store original fptr to backup, to call into original later
.align 2
	la      $v0, _installed_fptr_2	# Get the address we want to use to replace the previous fptr (pseudo-instruction)
	sw	$v0, 0($v1)		# Write our fptr so it gets called in all LMP control flow

_resume_original_control_flow:
	# Now that this is an epilog hook, we don't need a resume target anymore
	# We just conclude how the original code would have concluded...

	# These were the original instructions I smashed...
	# AFAICT the original code doesn't care about the return values in v0/v1...
	lw	$a3, 0x24($sp)		# Shows up in Ghidra as "local_4" aka -4, so 0x24 is calculated by 0x28 stack size (from addiu sp, -0x28) - 4
	lw	$s1, 0x20($sp)		# 0x28 stack size - 0x8
	lw	$s0, 0x1C($sp)		# 0x28 stack size - 0xC
.align 2
	jr	$a3			# Jump to the saved return/continue address
	addiu	$sp, 0x28		# Restore the stack pointer to remove the stack frame

# Reached via function pointer call where the global data storing the fptr was overwritten with this address
# This code is called on all HCI CMD control flow,
# and will check whether our VSC (0xFE22, OCF = 0x222) was passed
_installed_fptr_1:
	# Store arguments as backup on stack
	addiu	$sp, -0x20		# All other instances of addiu $sp, -X that I saw int the code were 0x8-aligned,
					# so I'm doing that here too out of an abundance of caution for possible alignment requirements
	sw	$a0, 0x00($sp)
	sw	$a1, 0x04($sp)
	sw	$a2, 0x08($sp)
	sw	$ra, 0x0C($sp)

	# At this point $a0 should hold a pointer to the buffer with the OGF_OCF at offset 0, len at offset 2, and data at offset 3
.align 2
	lhu	$v1, 0x0($a0)		# Store the OGF_OCF into $v1 (make sure to use *unsigned* LHU to avoid sign-extension!)
	cmpi	$v1, 0xfe22		# Check if it's our VSC (OCF = 0x222, unused by RTK AFAIK)
.align 2
	btnez	not_my_VSC

	# Save regs again, just in case...
	addiu	$sp, -0x20		# All other instances of addiu $sp, -X that I saw int the code were 0x8-aligned,
					# so I'm doing that here too out of an abundance of caution for possible alignment requirements
	sw	$a0, 0x04($sp)
	sw	$a1, 0x08($sp)
	sw	$a2, 0x0C($sp)
	sw	$a3, 0x10($sp)
	sw	$v0, 0x14($sp)
	sw	$v1, 0x18($sp)

	# Call the existing code's memcpy() to copy the data out of the HCI buf and into the LMP buf
	lbu	$a2, 0x02($a0)		# Load the length of data to copy into a2
	move	$a1, $a0		# Load the src base address from a0 into a1
	addiu	$a1, 0x03		# Actual src data starts at offset 3. memcpy() seems to handle unaligned data OK...
.align	2
	la      $a0, LMP_pkt_buf	# Load the dst into a0
.align	2
	lw	$v0, memcpy_addr	# Get address of function to call
	jalr	$v0                     # Jump with link, so it comes back here when done
	nop
	# Restore saved reg that we depend on (pointer to the HCI buffer)
	lw	$a0, 0x04($sp)

#TMP: MOVE ME BACK!
	# Send a HCI Vendor-specific event (0xFF) from Controller to Host
	# with a the data which is destined to be used for LMP packet sending, just to prove we're running the patched code and we got here
	# (Using this instead of a type 0x0F or 0x0E just makes Bumble ignore it, instead of getting its state machine confused.)
        # Call hci_evt_sender(0xff, &LMP_pkt_buf, <dynamic-size>)
	lbu	$a2, 0x02($a0)		# Set the 3rd arg to the size of the data that was copied into the LMP_pkt_buf by the memcpy() above
	li      $a0, 0xff		# Set the first arg to constant for HCI Event opcode
.align	2
	la      $a1, LMP_pkt_buf	# We're going to check back the LMP_pkt_buf contents
.align	2
	lw	$v0, hci_evt_sender_addr # Get address of function to call
	jalr	$v0                     # Jump with link, so it comes back here when done
	nop

# Call send_LMP_reply(	a0=0 (big_ol_struct-array index 0),
#			a1=ptr to LMP buffer (opcode as offset 0 of a ushort (so it can hold extended opcodes if need be))
#			a2=3 (len),
#			a4=3 (unknown meaning! always either 2 or 3, possibly something to do with originating or replying),
#			a5=0x64 (unknown meaning!), store at SP + 0x10 (based on observed behavior in send_LMP_FEATURES_REQ_or_RES and others)
#			a6=0 (unknown meaning!), store at SP + 0x14 (based on observed behavior in send_LMP_FEATURES_REQ_or_RES and others)
	li	$a0, 0
.align	2
	la      $a1, LMP_pkt_buf	# Set the second arg to address of the LMP_pkt_buf buffer with the data to be sent
	li	$a2, 0x0a		# length (making it 2-byte aligned just because I saw one example
					# for LMP_UNSNIFF_REQ which had a len of 2 even tho it was only 1 byte long (only the opcode))
	li	$a3, 3			# Unknown parameter that's always 2 or 3. Going with 3 since it's what was always used for 0x27 LMP_FEATURES_REQ
	# Make guaranteed space on the stack for args[4],[5]
	# I always saw extra space allocated (but not used) for args[0]-[3], so I'm doing the same
.align	2
	addiu	$sp, -0x18		# Allocate 0x18 bytes of stack space
	li	$v0, 0x64		# Load hardcoded value always used with 0x27 LMP_FEATURES_REQ (TODO: If other packets don't work, check this!)
	sw	$v0, 0x10($sp)		# Store this args[4] at SP+0x10 (as was seen in existing code)
	li	$v0, 0			# Load hardcoded value always used with 0x27 LMP_FEATURES_REQ (TODO: If other packets don't work, check this!)
	sw	$v0, 0x14($sp)		# Store this args[5] at SP+0x14 (as was seen in existing code)
.align 2
	lw	$v0, send_LMP_reply_addr# Get address of function to call
	jalr    $v0                     # Jump with link, so it comes back here when done
	nop

	# Remove space on the stack for args[4],[5]
.align	2
	addiu	$sp, 0x18

	# Restore regs after just in case save
	lw	$a0, 0x04($sp)
	lw	$a1, 0x08($sp)
	lw	$a2, 0x0C($sp)
	lw	$a3, 0x10($sp)
	lw	$v0, 0x14($sp)
	lw	$v1, 0x18($sp)
	addiu	$sp, 0x20

# This is the label where it will go on any VSC except 0xFE22
not_my_VSC:

	# Restore arguments from backups
	lw	$a1, 0x0C($sp)		# Restore my $ra backup...
	move	$ra, $a1		# ...because it's not possible to encode "lw $ra, 0x0C($sp)" in MIPS16e (despite there being a "sw $ra, <offset>($sp)" form!)
	lw	$a2, 0x08($sp)
	lw	$a1, 0x04($sp)
	lw	$a0, 0x00($sp)
	addiu	$sp, 0x20

	# Call to the original fptr that was in patch_target_1,
	# which we stored to backup_addr_1
.align 2
	lw	$v1, backup_addr_1
	lw	$v1, 0($v1)
	jrc	$v1

# This code is called on the path where incoming LMP packets are parsed
# The purpose of the code is:
# 1) To be used to confirm that a given device has seen or not seen an incoming LMP packet
# 2) To provide inspection capabilities to understand what arguments & buffer contents look like
#    (which can help with creating outgoing LMP capabilities)
_installed_fptr_2:
	# Store arguments as backup on stack

# Very very weird that if this alignment statement isn't here, patching fails...
.align 2
	addiu	$sp, -0x20		# All other instances of addiu $sp, -X that I saw int the code were 0x8-aligned,
					# so I'm doing that here too out of an abundance of caution for possible alignment requirements
	sw	$a0, 0x00($sp)
	sw	$a1, 0x04($sp)
	sw	$a2, 0x08($sp)
	sw	$s0, 0x0C($sp)
	sw	$s1, 0x10($sp)
	sw	$ra, 0x14($sp)		# It's OK to "sw $ra, offset($sp)", but be aware there's not a way to encode "lw $ra, offset($sp)"...


	# I don't know what I'm currently screwing up...but without this extra save/restore before/after function call, it behaves crazily...
	addiu	$sp, -0x10		# Assuming 0x8-alignment is required, because it was seen elsewhere

	sw	$a0, 0x00($sp)
	sw	$a1, 0x04($sp)
	sw	$a2, 0x08($sp)
	sw	$v0, 0x0C($sp)

	# Always memset() hci_evt_packet_log_buf to 0 for clarity before copying data in
	# (Should I try setting it to something like X to see uninitialized data?)
	li	$a2, 0x38		# Size of hci_evt_packet_log_buf
	li	$a1, 0xcc		# Value to memset to
.align	2
	la	$a0, hci_evt_packet_log_buf
.align	2
	lw	$v0, memset_addr	# Get address of function to call
	jalr	$v0                     # Jump with link, so it comes back here when done
	nop

	lw	$v0, 0x0C($sp)
	lw	$a2, 0x08($sp)
	lw	$a1, 0x04($sp)
	lw	$a0, 0x00($sp)
	addiu	$sp, 0x10

	# Copy data from the incoming LMP packet to the the hci_evt_packet_log_buf that we will send with HCI Event
	# a0 has some data structure (e.g. data_buf_pointer, unknown-arg2 (used as byte in 0x480 opcode-like), ushort-opcode-like)
.align 2
	la	$v0, hci_evt_packet_log_buf

.align 2
	lw	$v1, AAAA
	sw	$v1, 0x00($v0)		# Writing 'A's to the beginning, just so it's clear where the data starts in the buffer
	sw	$a0, 0x04($v0)		# Write the a0 pointer itself
	lw	$v1, 0x00($a0)		# Read data_buf_pointer
	sw	$v1, 0x08($v0)		# Store data_buf_pointer
	lw	$v1, 0x04($a0)		# Read the unknown-arg2 at offset 4
	sw	$v1, 0x0C($v0)		# Storing unknown-arg2 at previous store +4
	lh	$v1, 0x08($a0)		# Read the opcode-like ushort and 2 bytes more at offset 8
	sh	$v1, 0x10($v0)		# Storing at previous store +4
.align 2
	lw	$v1, BBBB
	sw	$v1, 0x14($v0)		# Writing 'B's to the end, just so it's clear where the data ends in the buffer

	# Save the a0 in s0 as a tmp, before it gets smashed again below
	move	$s0, $a0

	# Check if the opcode-like is 0x0480, the only LMP path we care about for now, and if not, don't include the extra data
.align 2
	lh	$v1, 0x10($v0)		# Load the opcode-like back into v1
	cmpi	$v1, 0x0480		# And only proceed to extra data collection if it's down the 0x480 path we care about
.align 2
	btnez	skip_extra_data_collection

	# The maximum possible size of an LMP packet according to Table 5.1 "Coding of the different LM PDUs" in Spec v 5.4
	# is 17 bytes, which includes the opcode. Since we're also trying to copy the 4-byte header (but getting 0s)
	# we'll copy 0x18 bytes (to be aligned) from the data_buf_pointer
	# Now copy 0x20 bytes of data from the data_buf_pointer (so I can see what the function would be seeing for various vars)
.align 2
	lw	$a0, 0x08($v0)		# Store data_buf_pointer into a0
	lw	$v1, 0x00($a0)		# Strangely this is always coming back as 0x00000000 instead of the first 4 bytes of LMP ACH header...
	sw	$v1, 0x18($v0)
	lw	$v1, 0x04($a0)
	sw	$v1, 0x1C($v0)
	lw	$v1, 0x08($a0)
	sw	$v1, 0x20($v0)
	lw	$v1, 0x0C($a0)
	sw	$v1, 0x24($v0)
	lw	$v1, 0x10($a0)
	sw	$v1, 0x28($v0)
	lw	$v1, 0x14($a0)
	sw	$v1, 0x2C($v0)
	lw	$v1, 0x18($a0)
	sw	$v1, 0x30($v0)
.align 2
	lw	$v1, CCCC
	sw	$v1, 0x34($v0)		# Writing 'C's to the end, just so it's clear where the data ends in the buffer

skip_extra_data_collection:

	# I don't know what I'm currently screwing up...but without this extra save/restore before/after function call, it crashes
	addiu	$sp, -0x10		# All other instances of addiu $sp, -X that I saw int the code were 0x8-aligned,
					# so I'm doing that here too out of an abundance of caution for possible alignment requirements
	sw	$a0, 0x00($sp)
	sw	$a1, 0x04($sp)
	sw	$a2, 0x08($sp)
	sw	$v0, 0x0C($sp)

	# Send a HCI vendor-specific event (0xFF) from Controller to Host
	# with a custom buffer hci_evt_packet_log_buf worth of data
        # Call hci_evt_sender(0xff, &hci_evt_packet_log_buf, 0x40)
	li      $a0, 0xff			# Set the first arg to constant for HCI Event opcode
.align	2
	la      $a1, hci_evt_packet_log_buf	# Set the second arg to address of the hci_evt_packet_log_buf buffer with the HCI Event data
	li      $a2, 0x38			# Set the third arg to the size of the hci_evt_packet_log_buf
.align 	2
	lw      $v0, hci_evt_sender_addr	# Get address of function to call
	jalr    $v0                     	# Jump with link, so it comes back here when done
	nop

	# I don't know what I'm currently screwing up...but without this extra save/restore before/after function call, it crashes
	lw	$v0, 0x0C($sp)
	lw	$a2, 0x08($sp)
	lw	$a1, 0x04($sp)
	lw	$a0, 0x00($sp)
	addiu	$sp, 0x10

	# Restore extra-saved a0
	move	$a0, $s0

	# Restore arguments from backups
	lw	$s1, 0x14($sp)		# Restore my $ra backup...
	move	$ra, $s1		# ...since there's no "lw $ra ..." options
	lw	$a0, 0x00($sp)
	lw	$a1, 0x04($sp)
	lw	$a2, 0x08($sp)
	lw	$s0, 0x0C($sp)
	lw	$s1, 0x10($sp)
.align 2
	addiu	$sp, 0x20		# All other instances of addiu $sp, -X that I saw int the code were 0x8-aligned,
					# so I'm doing that here too out of an abundance of caution for possible alignment requirements

	# Call to the original fptr that was in patch_target_2,
	# which we stored to backup_addr_2
.align 2
	lw	$v1, backup_addr_2
	lw	$v1, 0($v1)
	jrc	$v1

.align 2
patch_target_1:
        .word   0x80120f10		# Hook point in HCI_CMD_OGF_3F__Vendor_Specific__FUN_80030f1c (NULL by default)
patch_target_2:
        .word   0x8012aed4		# The pointer to the function "patch_replaces->assoc_w_tLMP()"
					# which is installed by the patches which replaces the original LMP handler
					# and which I want to replace, so I get called on every LMP packet

backup_addr_1:
	.word	0x80133ffc		# There's a gap at a higher address than where the stack starts, which we can safely assume no one else will use ;)
backup_addr_2:
	.word	0x80133ff8		# There's a gap at a higher address than where the stack starts, which we can safely assume no one else will use ;)

memcpy_addr:
	.word	0x8000e85d		# Address of the optimized_memcpy() in Ghidra (+1 for MIPS16e). Used by patches as well, so the address should be stable

memset_addr:
	.word	0x8000e98d		# Address of the memset() in Ghidra (+1 for MIPS16e). Used by patches as well, so the address should be stable

LMP_path_const:
	.word	0x00000480		# The "opcode-like" thing (I don't know what it is) that's checked to go down the LMP control flow path that we care about

send_LMP_reply_addr:
	.word	0x800611e5		# Address for send_LMP_reply() in Ghidra (+1 for MIPS16e)

# This is the buffer structure used by the send_LMP_reply() function in Ghidra
.align 2
LMP_pkt_buf:
	.byte	0x27			# raw opcode number - e.g. LMP_FEATURES_REQ = 0x27
	.byte	0x00			# Unknown uninitialized possible padding, possible used value. All I know is it didn't work till I added this in...
	.byte	0xde			# Maximum of 16 bytes of packet data
	.byte	0xad			# NOTE: Per the spec that's the max size, however in the future we'll want to make this bigger
	.byte	0xbe			#	so we can send over-sized malformed data (as long as we can confirm that doesn't crash the sender stack)
	.byte	0xef
	.byte	0xca
	.byte	0xfe
	.byte	0x13
	.byte	0x37
	.byte	0xde
	.byte	0xad
	.byte	0xbe
	.byte	0xef
	.byte	0xca
	.byte	0xfe
	.byte	0x13
	.byte	0x37

.align 2
hci_evt_sender_addr:
       .word	0x8001d071                 # Function used to send HCI Events from Controller to Host

# This is a 0x40 byte buffer, just to store 0x40 bytes of data about LMP packets that have been received,
# to send up to the Host for logging/visibility/sanity checking whether the recipient saw
# what we think the sender sent
.align 2
hci_evt_packet_log_buf:
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000

# Spare vars for misc use
.align 2
AAAA:
	.word	0x41414141
BBBB:
	.word	0x42424242
CCCC:
	.word	0x43434343		# Terminator for my script for printing bytes

