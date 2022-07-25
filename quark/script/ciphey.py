# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from ciphey import decrypt
from ciphey.iface import Config


def checkClearText(inputString: str) -> bool:
    """Check if the input string is encrypted.

    :param inputString: Input String
    :return: True/False
    """
    result = decrypt(Config().library_default().complete_config(), inputString)

    if inputString == result:
        return True
    else:
        return False
