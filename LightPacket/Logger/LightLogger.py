# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import logging
import sys
from ..Decoration.Colors import REDBG ,RESETBG ,YELLOW ,YELLOWBG ,RESET ,RED
from .Errors import *

class ErrorCode:
    INVALID_MAC = "E001"
    INVALID_DATA_TYPE = "E002"
    INVALID_DATA_LENGTH = "E003"
    INVALID_IP = "E004"
    NOT_FOUND = "E005"

    ERROR_MAP = {
        'E001': InvalidMacAddressError,
        'E002': InvalidDataTypeError,
        'E003': InvalidDataLengthError,
        'E004': InvalidIPAddressError,
        'E005': NotFoundError
    }

class WarningCode:
    NONHEXVALUE = "W001"

    WarningCodes = {
        NONHEXVALUE: "Invalid Hex-Decimal Value",
    }

    WARNING_MAP = {
        "W001": NONHEXVALUE,
    }

class Logger:
    def __init__(self, name="LightPacket"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            console = logging.StreamHandler(sys.stdout)
            console.setLevel(logging.DEBUG)
            self.logger.addHandler(console)


    def error(self, message, error_code=None, **kwargs):
        if error_code and error_code in ErrorCode.ERROR_MAP.keys():
            message = f"{REDBG}[{error_code}]{RESETBG}{RED} {message}{RESET}"

        error_class = ErrorCode.ERROR_MAP.get(error_code)
        if error_class:
            raise error_class(message)
        else:
            raise ValueError(f"Unknown error code: {error_code}")

    def warning(self, message,warning_code=None, **kwargs):
        if warning_code and warning_code in WarningCode.WarningCodes.keys():
            message = f"{YELLOWBG}[{warning_code}]{RESETBG}{YELLOW} {message}{RESET}"
        self.logger.warning(message, extra=kwargs)
