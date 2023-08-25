import ida_funcs
import idc
import ida_bytes
import idaapi

def get_function_list():
    
    function_count = ida_funcs.get_func_qty()
    function_list = []
    for i in range(function_count):
        function = ida_funcs.getn_func(i)
        if(function == None):
            raise f"function #{i:04X} referenced to a null function."
        function_list.append(function)

    return function_list

def get_function_code_blocks(function):
    result = []
    #print(f'[D] result.append([{function.start_ea},{idc.prev_head(function.end_ea)}])')
    result.append([function.start_ea,idc.prev_head(function.end_ea)])
    
    for i in function.tails:
        if(i != None):
            #print(f'[D] result.append([{i.start_ea},{idc.prev_head(i.end_ea)}])')
            result.append([i.start_ea,idc.prev_head(i.end_ea)])
    return result

def get_blocks_call(start_ea, end_ea):
    result = []
    ea = start_ea
    while ea < end_ea:
        if(not ida_bytes.is_code(ida_bytes.get_flags(ea))):
            ea = ea + 1
        else:
            insn = idaapi.insn_t()
            length = idaapi.decode_insn(insn, ea)
            name : str = insn.get_canon_mnem()
            if(name.startswith('call')):
                addr = idc.get_operand_value(ea,0)
                func = ida_funcs.get_func(addr)
                result.append(func)
                
            ea = ea + length
    return result

if __name__ == "__main__":
    fp = open('D:\graph_data1.txt','w+')
    
    functions = get_function_list()
    #print(f'[-] This file contains  {len(functions)} functions')
    for func in functions:
        code_blocks = get_function_code_blocks(func)
        parent_name = idc.get_func_name(func.start_ea)
        #print(f'[-] {parent_name} gets {len(code_blocks)} blocks')
        #print(f'[-] in {parent_name}')
        count = 0
        if(code_blocks == None):
            continue
        for i in code_blocks:
            #print(f'[-] reading #{count:03} tail...')
            count = count + 1
            callees = get_blocks_call(i[0],i[1])
            if(callees != None):
                #callees = list(set(callees))
                for j in callees:
                    if(j == None):
                        continue
                    child_name = idc.get_func_name(j.start_ea)
                    if(child_name == None):child_name = 'undefined'
                    fp.write(f'{parent_name},{child_name}\n')
    fp.close()
