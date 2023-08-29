# hed10nes-toolset

这个repo中存储了我在各种工作中处理各种内容的脚本、文档文件。

## 目录

### ida

这几个脚本是在mfc的flirt导入失败的时候顺手用的。

**exception_headers.h**：包含了win32的Exception结构，用于快速Y

**exception_code.py**：win32的Exception枚举值。

**ntdll.h**：部分结构

**tlhelp32.h**



#### sctipts

**call_graph.py**：分析idb文件中的call指令，并根据这些指令构建call列表文件。此脚本将创建`D:\graph_data1.txt`文件

*call_graph_visualization.py*：读取上述文件，构建函数调用图。需要在ida外手动调用

```
requirements:
networkx
matplotlib
pyvis
```

**jmp_parser.py**：对`jzjnz`、`call $+5`花指令的自动去除器

**ida_dexmm.py**：去除ida中的xmm指令

**revert_patched.py**：将ida中的所有被patch的字节恢复

### plugins

**GuLoaderPlugin.py**：针对于GuLoader的处理插件



#### ida



### vanilla

**thread_loop.c**：无限循环程序，展示当前程序中的线程。

**gs_tester.c**：获取gs寄存器，用于x86、x64检查

**Switch-Adapter.ps1**：切换指定适配器的网络信息，例如变更Ethernet适配器的IPv4配置
