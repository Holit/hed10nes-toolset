 #!/usr/bin/python
# IDApython script to solve GuLoader malware.
# this tool will help you with:
# 1. de-xmm code, which is junk at all
# 2. de -veh, which hijacked the control flows of correct flow.
# #other function shall be added further.
#Author: Jerry
# -*- coding: utf-8 -*-
import idaapi
import idc
import ida_nalt
import ida_idp
import ida_bytes
import ida_ua
import os
import ida_kernwin 
#################################
# Modify this xor byte.
byte_xor = 0x90
#################################
ins_blacklist = [
	0x00, # mov [eax], eax
	0x18, # mov [eax], ebx
	0x08, # mov [eax], ecx
	0x10, # mov [eax], edx
	0x28, # mov [eax], ebp
	0x30, # mov [eax], esi
	0x38, # mov [eax], edi
	0x03, # mov [ebx], eax
	0x1B, # mov [ebx], ebx
	0x0B, # mov [ebx], ecx
	0x13, # mov [ebx], edx
	0x2B, # mov [ebx], ebp
	0x33, # mov [ebx], esi
	0x3B, # mov [ebx], edi
	0x01, # mov [ecx], eax
	0x19, # mov [ecx], ebx
	0x09, # mov [ecx], ecx
	0x11, # mov [ecx], edx
	0x29, # mov [ecx], ebp
	0x31, # mov [ecx], esi
	0x39, # mov [ecx], edi
	0x02, # mov [edx], eax
	0x1A, # mov [edx], ebx
	0x0A, # mov [edx], ecx
	0x12, # mov [edx], edx
	0x2A, # mov [edx], ebp
	0x32, # mov [edx], esi
	0x3A, # mov [edx], edi
	0x06, # mov [esi], eax
	0x1E, # mov [esi], ebx
	0x0E, # mov [esi], ecx
	0x16, # mov [esi], edx
	0x2E, # mov [esi], ebp
	0x36, # mov [esi], esi
	0x3E, # mov [esi], edi
	0x07, # mov [edi], eax
	0x1F, # mov [edi], ebx
	0x0F, # mov [edi], ecx
	0x17, # mov [edi], edx
	0x2F, # mov [edi], ebp
	0x37, # mov [edi], esi
	0x3F # mov [edi], edi
]
xmm_junk = ['f2xm1','fabs', 'fadd', 'faddp', 'fbld', 'fbstp', 'fchs', 'fclex', 'fcmovb', 'fcmovbe', 'fcmove', 'fcmovnb', 
            'fcmovnbe', 'fcmovne', 'fcmovnu', 'fcmovu', 'fcom', 'fcomi', 'fcomip', 'fcomp', 'fcomp5', 'fcompp', 
            'fcos', 'fdecstp', 'fdisi', 'fdiv', 'fdivp', 'fdivr', 'fdivrp', 'femms', 'feni', 'ffree', 'ffreep', 
            'fiadd', 'ficom', 'ficomp', 'fidiv', 'fidivr', 'fild', 'fimul', 'fincstp', 'finit', 'fist', 'fistp', 
            'fisttp', 'fisub', 'fisubr', 'fld', 'fld1', 'fldcw', 'fldenv', 'fldl2e', 'fldl2t', 'fldlg2', 'fldln2', 
            'fldpi', 'fldz', 'fmul', 'fmulp', 'fnclex', 'fndisi', 'fneni', 'fninit', 'fnop', 'fnsave', 'fnstcw', 
            'fnstenv', 'fnstsw', 'fpatan', 'fprem', 'fprem1', 'fptan', 'frndint', 'frstor', 'fsave', 'fscale', 'fsetpm', 
            'fsin', 'fsincos', 'fsqrt', 'fst', 'fstcw', 'fstenv', 'fstp', 'fstp1', 'fstp8', 'fstp9', 'fstsw', 'fsub', 
            'fsubp', 'fsubr', 'fsubrp', 'ftst', 'fucom', 'fucomi', 'fucomip', 'fucomp', 'fucompp', 'fxam', 'fxch', 'fxch4', 
            'fxch7', 'fxrstor', 'fxsave', 'fxtract', 'fyl2x', 'fyl2xp1', 'pabsb', 'pabsd', 'packssdw', 'packsswb', 'packuswb', 
            'paddb', 'paddd', 'paddq', 'paddsb', 'paddsw', 'paddusb', 'paddusw', 'paddw', 'pand', 'pandn', 'pause', 'pavgb', 
            'pavgw', 'pcmpeqb', 'pcmpeqd', 'pcmpeqw', 'pcmpgtb', 'pcmpgtd', 'pcmpgtw', 'pextrw', 'pf2id', 'pf2iw', 'pfadd', 
            'pfcmpeq', 'pfcmpge', 'pfcmpgt', 'pfmax', 'pfmin', 'pfsub', 'phsubsw', 'pi2fw', 'pinsrw', 'pmaddwd', 'pmaxsw', 
            'pmaxub', 'pminsw', 'pminub', 'pmovmskb', 'pmulhuw', 'pmulhw', 'pmullw', 'pmuludq', 'por', 'prefetch', 'prefetchnta',
            'prefetcht0', 'prefetcht1', 'prefetcht2', 'prefetchw', 'prefetchwt1', 'psadbw', 'pshufd', 'pshufhw', 'pshuflw',
            'pshufw', 'psignb', 'pslld', 'psllq', 'psllw', 'psrad', 'psraw', 'psrld', 'psrlq', 'psrlw', 'psubb', 'psubd', 
            'psubq', 'psubsb', 'psubsw', 'psubusb', 'psubusw', 'psubw', 'punpckhbw', 'punpckhdq', 'punpckhwd', 'punpcklbw', 
            'punpckldq', 'punpcklwd', 'pxor']
jcc_jmp_insns=[
    #'ja', 'jae', 'jb', 'jbe', 'jc', 'jcxz', 'je', 'jecxz', 
    #'jg', 'jge', 'jl', 'jle', 'jna', 'jnae', 'jnb', 'jnbe', 
    #'jnc', 'jne', 'jng', 'jnge', 'jnl', 'jnle', 'jno', 'jnp', 
    #'jns', 'jnz', 'jo', 'jp', 'jpe', 'jpo', 'jrcxz', 'js', 'jz',
    'jmp',
]
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
    if(idc.next_head(ea) != ea+length):
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
    disasm : str = idc.generate_disasm_line(ea,0)
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

error_dict = []
def jmp_parser(ea):
    name : str = idc.print_insn_mnem(ea)
    disasm : str = idc.generate_disasm_line(ea,0)
    disasm = disasm.split(';')[0]
    if(any(x == name for x in jcc_jmp_insns)):
        # parser for jmp/jcc loc+1
        if(disasm.find('+') != -1):
            correct = True
            part2=disasm.split('+')[1]
            #print(part2)
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
                    if(not true_addr in error_dict):
                        print(f'[!]0x{ea:08X} jmp error: {true_addr:08X}, {target:08X}')
                        idaapi.del_items(true_addr,0,target - true_addr)
                        recreate_insn(target)
                        error_dict.append(true_addr)
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
    if(any(x == [idc.print_insn_mnem(ea), idc.print_insn_mnem(idc.next_head(ea))] for x in mutex_instructions) or \
        any(x == [idc.print_insn_mnem(idc.next_head(ea)), idc.print_insn_mnem(ea)] for x in mutex_instructions)):
        if(idc.get_operand_value(ea,0) == idc.get_operand_value(idc.next_head(ea),0)):
            #find correct jzjnz
            jcc_insn = idaapi.insn_t()
            length = idaapi.decode_insn(jcc_insn, ea)
            replace_jcc_with_jmp(idc.next_head(ea))
            nop_insn(ea)
            ea = idc.next_head(ea)
    pass

class GuLoaderSolverHook(idaapi.IDP_Hooks):
    def __init__(self):
        super(GuLoaderSolverHook, self).__init__()
    #broken here.
    def ev_emu_insn(self, insn):
        ea = insn.ea
        #insn = idaapi.insn_t()
        #length = idaapi.decode_insn(insn, ea)
        name : str = insn.get_canon_mnem()
        #print(f'0x{ea:08X}, {name}')
        if((ida_bytes.is_code(ida_bytes.get_flags(ea))) and \
           (any(x == name for x in xmm_junk)) and \
           ea <= 0x4000):
            insn_len = insn.size
            for i in range(insn_len):
                idaapi.patch_byte(ea + i, 0x90)
        elif(name.startswith('pushf')):
            insn2 = idaapi.insn_t()
            length2 = idaapi.decode_insn(insn2,ea + 0x5)
            name2 : str = insn2.get_canon_mnem()
            flag1 = ida_bytes.get_byte(ea + 0x5 - 2)
            if(name2.startswith('popf')):
                print(f'[!]0x{ea:08X} EXCEPTION_SINGLE_STEP')
                #ea = ea + 5
                insn3 = idaapi.insn_t()
                length3 = idaapi.decode_insn(insn3,ea + 0x5 + 0x1)
                target = ida_bytes.get_byte(ea + 0x5 + length3 + 2 + 1)
                '''
                ea + 0x5 + length3 + 2 + 1
                    |length of pushf and popf pair
                            | trap with paused at popf+1 insn, 
                            | popf
                            | cmp
                            | nop <- stops here, eip
                                    | offset 2
                                        |get one byte for xoring
                '''
                '''
                patch will start from ea + 0x5 + length3 to target length
                '''
                target = target ^ byte_xor
                if(target <= 0x20 ):
                    #find push xxx
                    '''
                    TODO
                    fully automation
                    1. backwards finding push.
                    idc.print_operand
                    2. recognize mov oprands and push oprands pair, and nop all push-pop 
                    3. from up to down, sentence by sentence.
                    '''
                    patch_begin = ea + 0x5 + length3 +1
                    x = 2
                    found = False
                    while( x <= 0x20):
                        if(idc.print_insn_mnem(ea -x) == 'push'):
                            patch_begin = ea - x
                            found = True
                            break
                        x = x + 1
                    if(not found):
                        patch_begin = ea + 0x5 + length3 +1
                    #print(f'#[!]0x80000004,{hex(ea)},{hex(target)},{target<=0x20},{hex(flag1)}')
                    #ida_bytes.set_cmt(0xcdb3a3,"this is a demo comment!", False)
                    ida_bytes.set_cmt(patch_begin,f"EXCEPTION_SINGLE_STEP, {hex(ea + 0x5 + length3)}, len = {hex(target)} ", True)
                    
                    idaapi.patch_byte(ea,0xEB)
                    idaapi.patch_byte(ea+1,target+ 0x5 + length3 + 2 -1 -2)

                    #for i in range(patch_begin, ea + 0x5 + length3 + target+1):
                    #    idaapi.patch_byte(i, 0x90)
                    #idc.create_insn(ea + 0x5 + length3 + 1)
                #tested, <= 0x20 is correct
                #print(f'[!]0x80000004,{hex(ea)},{hex(target)},{target<=0x20},{hex(flag1)}')
        elif (name.startswith('int')):
            if(insn.Op1.value == 0x3):
                target = ida_bytes.get_byte(ea + 1)
                target = target ^ byte_xor
                if(target <= 0x20):     #we've found that most of the correct CC mal-instruction shall target below 0x20.
                    print(f'[!]0x{ea:08X} EXCEPTION_BREAKPOINT')
                    ida_bytes.set_cmt(ea,f"EXCEPTION_BREAKPOINT, {hex(ea)}, len = {hex(target)} ", False)
                    #if INT3_METHOD = JMP
                    idaapi.patch_byte(ea,0xEB)
                    idaapi.patch_byte(ea+1,target-2)
                    #elif INT3_METHOD = NOPPING
                    #for i in range(ea, ea + target):
                    #    idaapi.patch_byte(i, 0x90)
                    #else
                    #except ...
                #tested, <= 0x20 is correct
                #print(f'[!]0x8000003,{hex(ea)},{hex(target)},{target<=0x20}')
        
        elif (name.startswith('mov')):
            if(ida_bytes.get_byte(ea) == 0x89):
                if(ida_bytes.get_byte(ea + 1) in ins_blacklist):
                    if(ida_bytes.get_byte(ea + 2) ^ 0x90 <= 0x20):
                        print(f'[!]0x{ea:08X} ACCESS_VIOLATION')
                        patch_begin = ea
                        x = 2
                        found = False
                        while( x <= 0x20):
                            if(idc.print_insn_mnem(ea -x) == 'push'):
                                patch_begin = ea - x
                                found = True
                                break
                            x = x + 1
                        if(not found):
                            patch_begin = ea
                        target = ida_bytes.get_byte(ea + 2) ^ byte_xor
                        ida_bytes.set_cmt(patch_begin,f"ACCESS_VIOLATION, {hex(ea)}, len = {hex(target)} ", True)
                        
                        idaapi.patch_byte(ea,0xEB)
                        idaapi.patch_byte(ea+1,target-2)
                        #for i in range(patch_begin, ea + target):
                        #    idaapi.patch_byte(i, 0x90)
        elif((ida_bytes.is_code(ida_bytes.get_flags(ea)))and (any(x == name for x in jcc_jmp_insns)) or name.startswith('jmp')):
            jmp_parser(ea)
        #call_parser(ea)
        #jzjnz_parser(ea)
        return False

class GuLoaderSolverPlugin(idaapi.plugin_t):

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = 'Fix everything of Guloader'
    help = 'IDApython script to solve GuLoader malware.'
    wanted_name = 'Guloader Solver'
    wanted_hotkey = ''        # waiting to determine
    hook = None
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        self.hook = None
        if not "Guloader" in ida_nalt.get_root_filename() or \
           idaapi.ph_get_id() != idaapi.PLFM_386: #Enable this plug-in to only work for specific file
            result = ida_kernwin.ask_buttons("Yes","No","Skip",0,"HIDECANCEL\nAccording to your filename, this file seems not a GuLoader malware.\n"
                                             f"filename = {ida_nalt.get_root_filename() }\n"
                                             f"id = {str(idaapi.ph_get_id())}\n"
                                             "If you do believe this is a correct file, click Yes to proceed, or click No to skip the plugin from loading.\n"
                                             "You can disable this plugin by editing the py file with constant 'STRICT'")
            STRICT = False
            if(STRICT or result == 0x0):
                return idaapi.PLUGIN_SKIP
            print(f'GuLoader plugin loaded successfully!')

        self.hook = GuLoaderSolverHook()
        self.hook.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.hook:
            self.hook.unhook()


def PLUGIN_ENTRY():
    return GuLoaderSolverPlugin()