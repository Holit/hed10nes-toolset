import ida_bytes
import ida_idaapi

def remove_patched_bytes(start_ea ,end_ea):
    ea = start_ea
    while ea < end_ea:
        if (ida_bytes.get_byte(ea) == 0x90 and ida_bytes.get_original_byte(ea) != 0x90):
            ida_bytes.patch_byte(ea, ida_bytes.get_original_byte(ea))
        ea = ea + 1

remove_patched_bytes(0,0x00D03E2B)
