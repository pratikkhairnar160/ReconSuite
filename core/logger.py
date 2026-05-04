"""
Logging setup with optional color and verbosity levels.
"""

import logging
import sys
from typing import Optional


# ANSI colour codes
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GREY   = "\033[90m"


class ColouredFormatter(logging.Formatter):
    LEVEL_COLOURS = {
        logging.DEBUG:    GREY,
        logging.INFO:     CYAN,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: BOLD + RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        colour = self.LEVEL_COLOURS.get(record.levelno, RESET)
        ts = self.formatTime(record, "%H:%M:%S")
        level_tag = f"{colour}[{record.levelname[0]}]{RESET}"
        return f"{GREY}{ts}{RESET} {level_tag} {record.getMessage()}"


class PlainFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = self.formatTime(record, "%H:%M:%S")
        return f"{ts} [{record.levelname[0]}] {record.getMessage()}"


def setup_logger(
    verbose: bool = False,
    quiet: bool = False,
    no_color: bool = False,
    name: str = "reconsuite",
) -> logging.Logger:
    log = logging.getLogger(name)
    log.handlers.clear()

    if quiet:
        log.setLevel(logging.WARNING)
    elif verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    formatter = PlainFormatter() if no_color else ColouredFormatter()
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.propagate = False
    return log


def get_logger(name: str = "reconsuite") -> logging.Logger:
    return logging.getLogger(name)
