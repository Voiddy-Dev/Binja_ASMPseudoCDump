#
# Description:  Binary Ninja plugin to decompile all the codebase in Pseudo C
# and dump it into a given directory, along with the linear assembly (.asm).
#
# Modified to include Assembly Dump.
#

import calendar
import ntpath
import os
import platform
import re
import time

from binaryninja.binaryview import BinaryView
from binaryninja.enums import DisassemblyOption, FunctionAnalysisSkipOverride
from binaryninja.function import DisassemblySettings, Function
from binaryninja.interaction import get_directory_name_input
from binaryninja.linearview import LinearViewCursor, LinearViewObject
from binaryninja.log import log_alert, log_error, log_info, log_warn
from binaryninja.plugin import BackgroundTaskThread, PluginCommand


class AsmPseudoCDump(BackgroundTaskThread):
    """AsmPseudoCDump class definition.

    Attributes:
        bv: A Binary Ninja BinaryView instance which is a view on binary data.
        msg: A string containing the message displayed when started.
        destination_path: A string containing the path of the folder where
            the code will be dumped.
    Class constants:
        FILE_SUFFIX: The suffix for Pseudo C files.
        ASM_SUFFIX: The suffix for Assembly files.
        MAX_PATH: Maximum path length (255).
    """

    FILE_SUFFIX = "c"
    ASM_SUFFIX = "asm"
    MAX_PATH = 255

    def __init__(self, bv: BinaryView, msg: str, destination_path: str):
        """Inits AsmPseudoCDump class"""
        BackgroundTaskThread.__init__(self, msg, can_cancel=True)
        self.bv = bv
        self.destination_path = destination_path

    def __get_function_name(self, function: Function) -> str:
        """Normalizes the function name for file creation."""
        function_symbol = self.bv.get_symbol_at(function.start)

        if (
            hasattr(function_symbol, "short_name")
            and (len(self.destination_path) + len(function_symbol.short_name))
            <= self.MAX_PATH
        ):
            return function_symbol.short_name
        elif (
            len(self.destination_path) + len("sub_%x" % (function.start))
            <= self.MAX_PATH
        ):
            return "sub_%x" % (function.start)
        else:
            if hasattr(function_symbol, "short_name"):
                raise ValueError(
                    "File name too long for function: "
                    f"{function_symbol.short_name!r}\n"
                    "Try using a different path"
                )
            else:
                raise ValueError(
                    "File name too long for function: "
                    f"sub_{function.start:x}\n"
                    "Try using a different path"
                )

    def __create_directory(self) -> str:
        """Creates a timestamped directory for the dump."""
        directory_name = "".join(
            (
                f"PseudoCDump_{ntpath.basename(self.bv.file.filename)}_",
                str(calendar.timegm(time.gmtime())),
            )
        )
        new_directory = os.path.join(self.destination_path, directory_name)
        os.mkdir(new_directory)

        return new_directory

    def run(self) -> None:
        """Iterates over functions and dumps both Pseudo C and Assembly."""
        self.destination_path = self.__create_directory()
        log_info(f"Number of functions to dump: {len(self.bv.functions)}")
        count = 1
        for function in self.bv.functions:
            try:
                if self.cancelled:
                    break

                function_name = self.__get_function_name(function)
                log_info(f"Dumping function {function_name}")
                self.progress = "Dumping Code: %d/%d" % (count, len(self.bv.functions))

                # Ensure analysis is done
                force_analysis(self.bv, function)

                # 1. Dump Pseudo C
                pcode = get_pseudo_c(self.bv, function)
                dest_c = os.path.join(
                    self.destination_path,
                    normalize_destination_file(function_name, self.FILE_SUFFIX),
                )
                with open(dest_c, "wb") as file:
                    file.write(bytes(pcode, "utf-8"))

                # 2. Dump Assembly
                asm_code = get_assembly(self.bv, function)
                dest_asm = os.path.join(
                    self.destination_path,
                    normalize_destination_file(function_name, self.ASM_SUFFIX),
                )
                with open(dest_asm, "wb") as file:
                    file.write(bytes(asm_code, "utf-8"))

                count += 1
            except Exception as e:
                log_error(f"Failed to dump function {function.name}: {e}")

        log_alert(f"Done \nFiles saved in {self.destination_path}")


def normalize_destination_file(destination_file: str, filename_suffix: str) -> str:
    """Normalizes the file name depending on the platform being run."""
    if "Windows" in platform.system():
        normalized_destination_file = ".".join(
            (re.sub(r'[><:"/\\|\?\*]', "_", destination_file), filename_suffix)
        )
    else:
        normalized_destination_file = ".".join(
            (re.sub(r"/", "_", destination_file), filename_suffix)
        )
    return normalized_destination_file


def force_analysis(bv: BinaryView, function: Function) -> None:
    """Forces analysis if it was skipped."""
    if function is not None and function.analysis_skipped:
        log_warn(f"Analyzing the skipped function {bv.get_symbol_at(function.start)}")
        function.analysis_skip_override = (
            FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis
        )
        bv.update_analysis_and_wait()


def get_pseudo_c(bv: BinaryView, function: Function) -> str:
    """Gets the Pseudo C of the function."""
    lines = []
    settings = DisassemblySettings()
    settings.set_option(DisassemblyOption.ShowAddress, True)
    settings.set_option(DisassemblyOption.WaitForIL, True)

    # Use language_representation for Pseudo C
    obj = LinearViewObject.language_representation(bv, settings)
    cursor_end = LinearViewCursor(obj)
    cursor_end.seek_to_address(function.highest_address)

    body = bv.get_next_linear_disassembly_lines(cursor_end)
    cursor_end.seek_to_address(function.highest_address)
    header = bv.get_previous_linear_disassembly_lines(cursor_end)

    for line in header:
        lines.append(f"{str(line)}\n")

    for line in body:
        lines.append(f"{str(line)}\n")

    return "".join(lines)


def get_assembly(bv: BinaryView, function: Function) -> str:
    """Gets the Linear Assembly of the function with offsets."""
    lines = []
    settings = DisassemblySettings()
    # Enable addresses (offsets)
    settings.set_option(DisassemblyOption.ShowAddress, True)
    settings.set_option(DisassemblyOption.WaitForIL, True)

    # get_linear_disassembly iterates over the function's linear view
    for line in function.get_linear_disassembly(settings):
        lines.append(f"{str(line)}\n")

    return "".join(lines)


def dump_pseudo_c_and_asm(bv: BinaryView, function=None) -> None:
    """Entry point for the plugin."""
    destination_path = get_directory_name_input("Destination")

    if destination_path is None:
        log_error("No directory was provided to save the dumps")
        return

    dump = AsmPseudoCDump(bv, "Starting the Code Dump...", destination_path)
    dump.start()


PluginCommand.register_for_address(
    "Pseudo C & ASM Dump",
    "Dumps Pseudo C and Assembly for the whole code base",
    dump_pseudo_c_and_asm,
)
