import argparse
import os
from elftools.elf.elffile import ELFFile
import re


def log_with_indent(level, type, message):
    if type == "DONE":
        color = "\033[32m[+]\033[0m"
    elif type == "ERROR":
        color = "\033[31m[!]\033[0m"
    elif type == "DOING":
        color = "\033[34m[*]\033[0m"
    elif type == "LIST":
        color = "\033[33m[-]\033[0m"
    print("%s%s: %s" % (level * "    ", color, message))

def get_linked_shared_libraries(binary, rootfs):
    """
    Get linked shared libraries of a binary
    :param binary: path to binary
    :return: list of linked shared libraries
    """
    libraries = []
    tmp_libraries = []
    invalid_libraries = []

    if binary is not None: 
        log_with_indent(1, "DOING", "Checking %s" % binary.split("/")[-1])
        with open(binary, "rb") as f:
            elffile = ELFFile(f)
            log_with_indent(1, "DOING", "Iterating sections")
            if elffile.num_sections() != 0:
                for section in elffile.iter_sections():
                    if section.name == ".dynamic":
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == "DT_NEEDED":
                                log_with_indent(2, "LIST", tag.needed)
                                tmp_libraries.append(tag.needed)

    end_flag = False
    for root, dirs, files in os.walk(rootfs):
        for file in files:
            # found librieas in binary and stored in tmp_libraries
            if tmp_libraries != [] and end_flag == False:
                for each_library in tmp_libraries:
                    if each_library in file:
                        if judge_shared_library(os.path.join(root, file)) == False:
                            invalid_libraries.append(os.path.join(root, file))
                        libraries.append(os.path.join(root, file))
                        tmp_libraries.remove(each_library)
                        if tmp_libraries == []:
                            end_flag = True
                            break
            # binary is not provided
            if binary is None:
                # print(file)
                if "so" in file and judge_shared_library(os.path.join(root, file)):
                    # print(os.path.join(root, file))
                    libraries.append(os.path.join(root, file))
            if end_flag == True:
                break
    if (end_flag == False and tmp_libraries != []) or invalid_libraries != []:
        for each_invalid_library in (tmp_libraries + invalid_libraries):
            log_with_indent(1, "ERROR", "Cannot find %s" % each_invalid_library.split("/")[-1])

    return libraries

def get_exported_functions(binary):
    """
    Get exported functions of a binary
    :param binary: path to binary
    :return: list of exported functions
    """
    functions = []
    with open(binary, "rb") as f:
        elffile = ELFFile(f)
        dynsym = elffile.get_section_by_name(".dynsym")
        if dynsym is None:
            symtab = elffile.get_section_by_name(".symtab")
            if symtab is None:
                log_with_indent(1, "ERROR", "Cannot find .dynsym or .symtab section in %s" % binary.split("/")[-1])
            else:
                symbols = symtab.get_symbol_by_name()
                for symbol in symbols:
                    if symbol.entry.st_info.bind == "STB_GLOBAL":
                        functions.append(symbol.name)
        else:
            symbols = dynsym.get_symbol_by_name()
            for symbol in symbols:
                if symbol.entry.st_info.bind == "STB_GLOBAL":
                    functions.append(symbol.name)
    print(binary, functions == [])
    return functions

def judge_shared_library(binary):
    """
    Judge whether a binary is a shared library
    :param binary: path to binary
    :return: True or False
    """
    # log_with_indent(2, "DOING", "Checking %s" % binary.split("/")[-1])
    with open(binary, "rb") as f:
        try:
            elffile = ELFFile(f)
            if elffile.header.e_type == "ET_DYN":
                return True
        except:
            # print("ERROR: %s is not a valid ELF file" % binary)
            return False
    return False

def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-f', '--function', type=str, required=True, help='function name')
    parser.add_argument('-r', '--rootfs', type=str, required=True, help='rootfs path')
    parser.add_argument('-b', '--binary', type=str, required=False, help='binary path')

    args = parser.parse_args()

    # get absolute path of binary
    try:
        binary_path = os.path.abspath(args.binary)
    except:
        binary_path = None

    # get absolute path of rootfs
    rootfs_path = os.path.abspath(args.rootfs)

    # get all linked shared libraries of binary
    libraries = get_linked_shared_libraries(binary_path, rootfs_path)

    for each_library in libraries:
        log_with_indent(1, "DOING", "Checking %s" % each_library.split("/")[-1])
        functions = get_exported_functions(each_library)
        if args.function in functions:
            log_with_indent(1, "DONE", "Found %s in %s" % (args.function, each_library.split("/")[-1]))
    
    log_with_indent(1, "DONE", "Done")
        
if __name__ == '__main__':
    main()