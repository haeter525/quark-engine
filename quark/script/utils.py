# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.


def getLength(argument: str) -> str:
    # TODO - Docstring
    # TODO - Test

    # Check if the argument is already wrapped by length() API
    indexOfDescriptor = argument.find("(")

    if indexOfDescriptor > 0:
        classAndMethodName = argument[:indexOfDescriptor]
    else:
        classAndMethodName = ""

    if classAndMethodName.endswith("length"):
        return argument
    else:
        return f"Ljava/lang/String;->length()I({argument})"
