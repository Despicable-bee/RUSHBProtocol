# Standard Libs
from typing import Optional
from typing import List
from typing import Dict

from enum import Enum
from enum import auto

from multiprocessing import Process
from multiprocessing import Queue

import socket
import sys
import os

import time

# * DEBUG VARIABLES ------------------------------------------------------------

__filename__ = 'RUSHBSvr.py'
__DEBUG_MODE_ENABLED__ = True

# * ENUMS ----------------------------------------------------------------------

class RUSHBPacketInitState:
    PACKET_INIT_OK = auto()
    PACKET_INIT_FAILED = auto()

# * HELPERS --------------------------------------------------------------------

class GenericErrorHandler(object):
    def __init__(self):
        pass

    def debug_print_error(self, filename: str, className: str, methodName: str, 
            exception: Exception, lineNum: int):
        """ General purpose debug error printer. 
        
        ARGS:
        - filename: The name of the file this error originates from
        - className: The name of the class the error is from
        - methodName: The name of the method this error is from
        - exception: The exception raised during runtime
        - lineNum: The line number the error occurred on (within the scope
                of the try catch)
        """
        print("ERROR:\n\t\
                File -> [ {} ]\n\t\
                Class -> [ {} ]\n\t\
                Method -> [ {} ]\n\t\
                Line Num -> [ {} ]".format(filename, className, 
                        methodName, lineNum))
        
        print("EXCEPTION: {}".format(exception))

class DebugLinePrinter(object):
    def __init__(self):
        pass

    def debug_message_line_print(self, filename: str):
        print("\nDEBUG MESSAGE " + "-" * (79 - len("DEBUG MESSAGE")) )
        print("Filename: {}, Linenum: {}".format(filename, 
                sys._getframe().f_back.f_lineno))   # type: ignore