# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import copy
import re
import shutil
import subprocess
from ast import Str
from os import F_OK, PathLike, access, mkdir
from xmlrpc.client import Boolean

from quark.config import COMPATIBLE_RAZIN_VERSIONS, RIZIN_COMMIT, RIZIN_DIR
from quark.utils.pprint import (
    clear_the_last_line,
    print_error,
    print_info,
    print_success,
)


def remove_dup_list(element):
    """
    Remove the duplicate elements in  given list.
    """
    return list(set(element))


def contains(subset_to_check, target_list):
    """
    Check the sequence pattern within two list.
    -----------------------------------------------------------------
    subset_to_check = ["getCellLocation", "sendTextMessage"]
    target_list = ["put", "getCellLocation", "query", "sendTextMessage"]
    then it will return true.
    -----------------------------------------------------------------
    subset_to_check = ["getCellLocation", "sendTextMessage"]
    target_list = ["sendTextMessage", "put", "getCellLocation", "query"]
    then it will return False.
    """

    target_copy = copy.copy(target_list)

    # Delete elements that do not exist in the subset_to_check list
    for item in target_copy:
        if item not in subset_to_check:
            target_copy.remove(item)

    for i in range(len(target_copy) - len(subset_to_check) + 1):
        for j in range(len(subset_to_check)):
            if target_copy[i + j] != subset_to_check[j]:
                break
        else:
            return True
    return False


def descriptor_to_androguard_format(descriptor):
    if "(" not in descriptor or ")" not in descriptor:
        raise ValueError(f"Invalid descriptor. {descriptor}")

    delimiter = descriptor.index(")")

    arg_str = descriptor[:delimiter]
    args = re.findall(r"L.+?;|[ZBCSIJFD]|\[", arg_str)

    new_descriptor = "(" + " ".join(args) + descriptor[delimiter:]
    new_descriptor = re.sub(r"\[ ", "[", new_descriptor)

    return new_descriptor


def execute_command(command, stderr=subprocess.PIPE, cwd=None):
    """
    Execute a given command and yield the messages from the standard output.

    :param command: a list of strings which is the command to execute
    :param cwd: a PathLike object which is the working directory. Defaults to
    None
    :raises subprocess.CalledProcessError: if the process terminates with a
    non-zero return code
    :yield: a string holding a line of message in the standard output
    """
    process = subprocess.Popen(
        command,
        bufsize=1,
        stdout=subprocess.PIPE,
        stderr=stderr,
        universal_newlines=True,
        cwd=cwd,
    )

    line = ""
    while True:
        char = process.stdout.read(1)
        if char == "\n" or char == "\r":
            clear_the_last_line()
            yield line
            line = ""
            continue

        elif char == "":
            break

        line = line + char

    process.stdout.close()
    return_code = process.wait()

    if return_code:
        error_messages = ""
        if stderr == subprocess.PIPE:
            for message in process.stderr.readlines():
                error_messages = error_messages + message

        raise subprocess.CalledProcessError(
            return_code, command, stderr=error_messages
        )

    if stderr == subprocess.PIPE:
        process.stderr.close()


def get_rizin_version(rizin_path) -> Str:
    """
    Get the version number of the Rizin instance in the path.

    :param rizin_path: a path to the Rizin executable
    :return: the version number of the Rizin instance
    """
    try:
        process = subprocess.run(
            [rizin_path, "-v"], timeout=5, check=True, stdout=subprocess.PIPE
        )
        result = str(process.stdout)

        matched_versions = re.finditer(
            r"[0-9]+\.[0-9]+\.[0-9]+", result[: result.index("@")]
        )
        first_matched = next(matched_versions, None)

        if first_matched:
            return first_matched.group(0)
        else:
            return None

    except BaseException:
        return None


def download_rizin(target_path) -> Boolean:
    """
    Download the source code of Rizin into the specified path. If a file or
    folder already exists, this function will remove them.

    :param target_path: a PathLike object specifying the location to save the
    downloaded files
    :return: a boolean indicating if the operation finishes without errors
    """
    if access(target_path, F_OK):
        shutil.rmtree(target_path)
        mkdir(target_path)

    try:
        print()

        for line in execute_command(
            [
                "git",
                "clone",
                "--progress",
                "https://github.com/rizinorg/rizin",
                target_path,
            ],
            stderr=subprocess.STDOUT,
        ):
            print_info(line)

        return True

    except subprocess.CalledProcessError as error:
        print_error("An error occurred when downloading Rizin.\n")

    return False


def update_rizin(source_path, target_commit) -> Boolean:
    """
    Checkout the specified commit in the Rizin repository. Then, compile the
    source code to build a Rizin executable.

    :param source_path: a PathLike object specifying the location to the
    source code
    :param target_commit: a hash value representing a valid commit in the
    repository
    :return: a boolean indicating the operation is success or not
    """

    try:
        print()

        # Checkout to target commit
        for line in execute_command(
            ["git", "checkout", target_commit], cwd=source_path
        ):
            print_info(line)

        # Remove the last build
        for line in execute_command(["rm", "-rf", "build"], cwd=source_path):
            print_info(line)

        # Clean out old subproject
        for line in execute_command(
            ["git", "clean", "-dxff", "subprojects/"], cwd=source_path
        ):
            print_info(line)

    except subprocess.CalledProcessError as error:
        print_error("An error occurred when updating Rizin.\n")

        for line in error.stderr.decode().splitlines():
            print_error(line)

        return False

    # Compile Rizin
    try:
        print()

        # Configure
        for line in execute_command(
            ["meson", "--buildtype=release", "build"], cwd=source_path
        ):
            print_info(line)

        # Compile the source code
        for line in execute_command(
            ["meson", "compile", "-C", "build"], cwd=source_path
        ):
            print_info(line)

        return True

    except subprocess.CalledProcessError as error:
        print_error("An error occurred when updating Rizin.\n")

        for line in error.stderr.decode().splitlines():
            print_error(line)

        return False


def find_rizin_instance(
    rizin_source_path: PathLike = RIZIN_DIR,
    target_commit: Str = RIZIN_COMMIT,
    disable_rizin_installation: Boolean = False,
) -> Str:
    """
    Search the system PATH and the Quark directory (~/.quark-engine)
    respectively to find an appropriate Rizin executable. If none of them are
    usable and the user doesn't disable the automatic installation feature,
    this method will download the source code and compile a Rizin executable
    for Quark.

    :param rizin_source_path: a path to the source code of Rizin. Defaults to
    RIZIN_DIR
    :param target_commit: a commmit specifying the Rizin version to compile.
    Defaults to RIZIN_COMMIT
    :param disable_rizin_installation: a flag to disable the automatic
    installation of Rizin. Defaults to False
    :return: a path if an appropriate Rizin executable is found, otherwise
    None
    """

    # Search Rizin in PATH
    which_result = shutil.which("rizin")
    if which_result:
        version = get_rizin_version(which_result)
        if version in COMPATIBLE_RAZIN_VERSIONS:
            return which_result

    # Otherwise, search the home path
    rizin_executable_path = rizin_source_path + "build/binrz/rizin/rizin"
    current_version = get_rizin_version(rizin_executable_path)

    if not current_version and not disable_rizin_installation:
        print_info("Cannot find a compatible Rizin instance.")
        print_info("Automatically install Rizin into the Quark directory.")
        for _ in range(3):
            result = download_rizin(rizin_source_path)
            if result:
                break

        result = update_rizin(rizin_source_path, target_commit)
        if result:
            print_success("Successfully install Rizin.")
            return rizin_executable_path
        else:
            return None

    if not current_version:
        return None

    if current_version in COMPATIBLE_RAZIN_VERSIONS:
        return rizin_executable_path

    # The current version is not compatible
    print_info(
        "Find an outdated Rizin executable in the Quark directory. Try to"
        + " update it."
    )

    if disable_rizin_installation:
        return rizin_executable_path
    else:
        # Update and compile the source code
        result = update_rizin(rizin_source_path, target_commit)
        if result:
            return rizin_executable_path
        else:
            return None
