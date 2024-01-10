import argparse
import os
import r2pipe

def log_with_indent(level: int, log_type: str, message: str, flush: bool = False) -> None:
    color_map = {
        "DONE": "\033[32m[+]\033[0m",
        "ERROR": "\033[31m[!]\033[0m",
        "DOING": "\033[34m[*]\033[0m",
        "LIST": "\033[33m[-]\033[0m"
    }
    color = color_map.get(log_type, "")
    if flush:
        print(f"\r{'    ' * level}{color}: {message}", end="", flush=True)
    else:
        print(f"{'    ' * level}{color}: {message}")


def get_linked_shared_libraries(binary: str, rootfs: str) -> list[str]:
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
    else:
        log_with_indent(1, "ERROR", "Binary is not provided, checking all libraries in rootfs")

    end_flag = False
    for root, dirs, files in os.walk(rootfs):
        for file in files:
            # found librieas in binary and stored in tmp_libraries
            if tmp_libraries != [] and end_flag == False:
                for each_library in tmp_libraries:
                    if each_library in file:
                        if judge_shared_library(os.path.join(root, file)) == False:
                            # print(os.path.join(root, file))
                            invalid_libraries.append(os.path.join(root, file))
                        libraries.append(os.path.join(root, file))
                        tmp_libraries.remove(each_library)
                        if tmp_libraries == []:
                            end_flag = True
                            break
            # binary is not provided
            if binary is None:
                if "so" in file and judge_shared_library(os.path.join(root, file)):
                    libraries.append(os.path.join(root, file))
            if end_flag == True:
                break

    log_with_indent(1, "DONE", "Found %d libraries in rootfs" % len(libraries))        
    
    if (end_flag == False and tmp_libraries != []) or invalid_libraries != []:
        for each_invalid_library in (tmp_libraries + invalid_libraries):
            log_with_indent(1, "ERROR", "Cannot find %s" % each_invalid_library.split("/")[-1])

    return libraries

def judge_function_exported(library: str, function_name: str) -> bool:
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

def judge_shared_library(binary: str) -> bool:
    """
    Judge whether a binary is a shared library
    :param binary: path to binary
    :return: True or False
    """
    try:
        r2 = r2pipe.open(binary, flags=["-2"])
    except:
        return False
    # binary is a shared library
    if r2.cmd("ih~ELF") != "" and r2.cmd("i~DYN") != "":
        r2.quit()
        return True
    else:
        r2.quit()
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

    # find function in libraries
    result = []
    for i, each_library in enumerate(libraries):
        log_with_indent(1, "DOING", "Checking {} / {} {:<30}".format(i + 1, len(libraries), each_library.split("/")[-1]), flush=True)
        flag = judge_function_exported(each_library, args.function)
        if flag == True:
            result.append(each_library)
    print("\n")
    log_with_indent(1, "DONE", "Done")
    for each in result:
        log_with_indent(2, "DONE", "Found %s in %s" % (args.function, each.split("/")[-1]))
        
if __name__ == '__main__':
    main()
