#IDA脚本，用于清除某代码段内的xmm垃圾指令


import idautils
import idaapi
import ida_bytes

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
def nop_xmm_instructions(start_ea, end_ea):
    # 遍历指定段内的所有指令
    ea = start_ea
    while(ea < end_ea):
        #如果当前地址为代码
        if(ida_bytes.is_code(ida_bytes.get_flags(ea))):
            insn = idaapi.insn_t()
            # 获取当前地址处的指令
            length = idaapi.decode_insn(insn, ea)
            name = insn.get_canon_mnem()
            if name is not None:
                if(any(x == name for x in xmm_junk)):
                    #print(name)
                    # 计算指令的长度
                    insn_len = insn.size
                    # 将指令替换为nop指令
                    for i in range(insn_len):
                        idaapi.patch_byte(ea + i, 0x90)
            ea = ea + length
        else:
            ea = ea + 1
    
start_address = 0x400
end_address = 0x00002D6E

# 删除指定段中的xmm操作指令
nop_xmm_instructions(start_address, end_address)
