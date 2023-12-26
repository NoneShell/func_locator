from elftools.elf.elffile import ELFFile

# 打开ELF文件
with open('./squash-rootfs/lib/private/libcms_cli.so', 'rb') as f:
    elf = ELFFile(f)

    
    # 获取全局符号表
    symtab = elf.get_section(0)

    # 遍历全局符号表中的符号条目
    for sym in symtab.iter_symbols():
        print(sym.name, sym.entry.st_value, sym.entry.st_size)