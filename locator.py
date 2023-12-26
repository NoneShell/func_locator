import argparse
import os
from elftools.elf.elffile import ELFFile
import r2pipe


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
            r2 = r2pipe.open(binary, flags=["-2"])
            tmp_libraries = r2.cmdj("ilj")
            r2.quit()
        log_with_indent(1, "DONE", "Found %d libraries in %s" % (len(tmp_libraries), binary.split("/")[-1]))

    end_flag = False
    for root, dirs, files in os.walk(rootfs):
        for file in files:
            # found librieas in binary and stored in tmp_libraries
            if tmp_libraries != [] and end_flag == False:
                for each_library in tmp_libraries:
                    if each_library in file:
                        if judge_shared_library(os.path.join(root, file)) == False:
                            print(os.path.join(root, file))
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

def judge_function_exported(library, function_name):
    """
    Judge whether a function is exported in a library
    :param library: path to library
    :param function: function name
    :return: True or False
    """
    r2 = r2pipe.open(library, flags=["-2"])
    if r2.cmd("iE~%s" % function_name) != "":
        r2.quit()
        return True
    else:
        r2.quit()
        return False

def judge_shared_library(binary):
    """
    Judge whether a binary is a shared library
    :param binary: path to binary
    :return: True or False
    """
    # log_with_indent(2, "DOING", "Checking %s" % binary.split("/")[-1])
    r2 = r2pipe.open(binary, flags=["-2"])
    if r2.cmd("ih~ELF") != "" and r2.cmd("i~DYN") != "":
        r2.quit()
        # log_with_indent(2, "DONE", "Found %s is a shared library" % binary.split("/")[-1])
        return True
    else:
        r2.quit()
        # log_with_indent(2, "DONE", "Found %s is not a shared library" % binary.split("/")[-1])
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

    result = []
    for each_library in libraries:
        log_with_indent(1, "DOING", "Checking %s" % each_library.split("/")[-1])
        flag = judge_function_exported(each_library, args.function)
        if flag == True:
            # log_with_indent(1, "DONE", "Found %s in %s" % (args.function, each_library.split("/")[-1]))
            result.append(each_library)
    
    log_with_indent(1, "DONE", "Done")
    for each in result:
        log_with_indent(2, "DONE", "Found %s in %s" % (args.function, each.split("/")[-1]))
        
if __name__ == '__main__':
    main()