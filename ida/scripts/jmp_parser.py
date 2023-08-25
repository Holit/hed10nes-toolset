import idaapi
import idc
import ida_bytes

def recreate_insn(ea):
    length = idc.create_insn(ea)
    i = 0
    while(length == 0):
        idaapi.del_items(ea,0,i)
        length = idc.create_insn(ea)
        i = i + 1
        if(i > 16):
            print(f'[!]failed! 0x{ea:X}, too many attempts')
            return 
    insn = idaapi.insn_t()
    length = idaapi.decode_insn(insn, ea)
    if(next_head(ea) != ea+length):
        recreate_insn(ea+length)

def replace_jcc_with_jmp(address):
    jcc_insn = idaapi.insn_t()
    length = idaapi.decode_insn(jcc_insn, address)
    if length == 0:
        raise f'Unable to decode command 0x{address:X}'
    if(length != 2):
        print(f'[!] 0x{address:X} Warning! Incompatible mutex jump size, further operation required.')
    target_address = jcc_insn.Op1.addr
    recreate_insn(target_address)
    jmp_bytes = b"\xEB" + (target_address - (address + 2)).to_bytes(1, byteorder='little', signed=True)
    idaapi.patch_bytes(address, jmp_bytes)
    ida_bytes.set_cmt(address, f"jzjnz, 0x{address:08X}", True)

def nop_insn(ea):
    insn = idaapi.insn_t()
    length = idaapi.decode_insn(insn, ea)
    if length == 0:
        raise f'Unable to decode command 0x{ea:X}'
    i = ea
    while i < ea+length:
        idaapi.patch_byte(i, 0x90)
        i = i + 1
def call_parser(ea):
    call_insns = [ 'call' ]
    
    name : str = idc.print_insn_mnem(ea)
    disasm : str = generate_disasm_line(ea,0)
    if(any(x == name for x in call_insns)):
        # parser for jmp/jcc loc+1
        if(disasm.find('+') != -1):
            correct = True
            part2=disasm.split('+')[1]
            _part2 = ''
            try:
                _part2 = str(int(part2))
            except ValueError:
                correct = False
            if(correct and _part2 == part2 ):
                #find correct ins
                target = idc.get_operand_value(ea,0)
                true_addr = idc.prev_head(target)
                if(target != true_addr):
                    #print(f'[!]{ea:#X} jmp error: {true_addr:#X}, {target:#X}')
                    idaapi.del_items(true_addr,0,target - true_addr)
                    recreate_insn(target)
    pass
def jmp_parser(ea):
    
    jcc_jmp_insns=[
        'ja', 'jae', 'jb', 'jbe', 'jc', 'jcxz', 'je', 'jecxz', 
        'jg', 'jge', 'jl', 'jle', 'jna', 'jnae', 'jnb', 'jnbe', 
        'jnc', 'jne', 'jng', 'jnge', 'jnl', 'jnle', 'jno', 'jnp', 
        'jns', 'jnz', 'jo', 'jp', 'jpe', 'jpo', 'jrcxz', 'js', 'jz',
        'jmp',
    ]

    name : str = idc.print_insn_mnem(ea)
    disasm : str = generate_disasm_line(ea,0)
    if(any(x == name for x in jcc_jmp_insns)):
        # parser for jmp/jcc loc+1
        if(disasm.find('+') != -1):
            correct = True
            part2=disasm.split('+')[1]
            _part2 = ''
            try:
                _part2 = str(int(part2))
            except ValueError:
                correct = False
            if(correct and _part2 == part2 ):
                #find correct ins
                target = idc.get_operand_value(ea,0)
                true_addr = idc.prev_head(target)
                if(target != true_addr):
                    #print(f'[!]{ea:#X} jmp error: {true_addr:#X}, {target:#X}')
                    idaapi.del_items(true_addr,0,target - true_addr)
                    recreate_insn(target)
    pass
def jzjnz_parser(ea):
    
    mutex_instructions = [
        ['ja', 'jbe'],  # Jump if Above, Jump if Below or Equal
        ['jae', 'jb'],  # Jump if Above or Equal, Jump if Below
        ['jg', 'jle'],  # Jump if Greater, Jump if Less or Equal
        ['jge', 'jl'],  # Jump if Greater or Equal, Jump if Less
        ['jna', 'jbe'],  # Jump if Not Above, Jump if Below or Equal
        ['jnae', 'jb'],  # Jump if Not Above or Equal, Jump if Below
        ['jnb', 'jae'],  # Jump if Not Below, Jump if Above or Equal
        ['jnc', 'jc'],  # Jump if Not Carry, Jump if Carry
        ['jne', 'je'],  # Jump if Not Equal, Jump if Equal
        ['jng', 'jge'],  # Jump if Not Greater, Jump if Greater or Equal
        ['jnl', 'jl'],  # Jump if Not Less, Jump if Less
        ['jno', 'jo'],  # Jump if Not Overflow, Jump if Overflow
        ['jnp', 'jp'],  # Jump if Not Parity, Jump if Parity
        ['jns', 'js'],  # Jump if Not Sign, Jump if Sign
        ['jnz', 'jz'],  # Jump if Not Zero, Jump if Zero
    ]
    #parser for jzjnz:
    if(any(x == [idc.print_insn_mnem(ea), idc.print_insn_mnem(next_head(ea))] for x in mutex_instructions) or \
        any(x == [idc.print_insn_mnem(next_head(ea)), idc.print_insn_mnem(ea)] for x in mutex_instructions)):
        if(idc.get_operand_value(ea,0) == idc.get_operand_value(next_head(ea),0)):
            #find correct jzjnz
            jcc_insn = idaapi.insn_t()
            length = idaapi.decode_insn(jcc_insn, ea)
            replace_jcc_with_jmp(next_head(ea))
            nop_insn(ea)
            ea = idc.next_head(ea)
    pass
def analysis(start_ea, end_ea):
    ea = start_ea
    #idaapi.show_wait_box(f'HIDECANCEL solve all from {start_ea} to {end_ea}')

    while(ea < end_ea):
        jmp_parser(ea)
        call_parser(ea)
        jzjnz_parser(ea)
        ea = idc.next_head(ea)

t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
if idaapi.read_selection(view, t0, t1):
    start, end = t0.place(view).toea(), t1.place(view).toea()
    analysis(start,end)
#call_parser(0x0040127B)