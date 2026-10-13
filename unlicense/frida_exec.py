import ctypes
import functools
import logging
import struct
import threading
from ctypes import wintypes
from importlib import resources
from pathlib import Path
from typing import (List, Callable, Dict, Any, Optional, Tuple)

import frida
import frida.core

from .process_control import (ProcessController, Architecture, MemoryRange,
                              QueryProcessMemoryError, ReadProcessMemoryError,
                              WriteProcessMemoryError)

LOG = logging.getLogger(__name__)
# See issue #7: messages cannot exceed 128MiB
MAX_DATA_CHUNK_SIZE = 64 * 1024 * 1024

OepReachedCallback = Callable[[int, int, bool], None]


class FridaProcessController(ProcessController):

    def __init__(self, pid: int, main_module_name: str,
                 frida_session: frida.core.Session,
                 frida_script: frida.core.Script):
        frida_rpc = frida_script.exports

        # Initialize ProcessController
        super().__init__(pid, main_module_name,
                         _str_to_architecture(frida_rpc.get_architecture()),
                         frida_rpc.get_pointer_size(),
                         frida_rpc.get_page_size())

        # Initialize FridaProcessController specifics
        self._frida_rpc = frida_rpc
        self._frida_session = frida_session
        self.process_exited = threading.Event()
        self._exported_functions_cache: Optional[Dict[int, Dict[str,
                                                                Any]]] = None

    def find_module_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        value: Optional[Dict[str,
                             Any]] = self._frida_rpc.find_module_by_address(
                                 hex(address))
        return value

    def find_range_by_address(
            self,
            address: int,
            include_data: bool = False) -> Optional[MemoryRange]:
        value: Optional[Dict[str,
                             Any]] = self._frida_rpc.find_range_by_address(
                                 hex(address))
        if value is None:
            return None
        return self._frida_range_to_mem_range(value, include_data)

    def find_export_by_name(self, module_name: str,
                            export_name: str) -> Optional[int]:
        export_address: Optional[str] = self._frida_rpc.find_export_by_name(
            module_name, export_name)
        if export_address is None:
            return None
        return int(export_address, 16)

    def enumerate_modules(self) -> List[str]:
        value: List[str] = self._frida_rpc.enumerate_modules()
        return value

    def enumerate_module_ranges(
            self,
            module_name: str,
            include_data: bool = False) -> List[MemoryRange]:

        def convert_range(dict_range: Dict[str, Any]) -> MemoryRange:
            return self._frida_range_to_mem_range(dict_range, include_data)

        value: List[Dict[str, Any]] = self._frida_rpc.enumerate_module_ranges(
            module_name)
        return list(map(convert_range, value))

    def enumerate_exported_functions(self,
                                     update_cache: bool = False
                                     ) -> Dict[int, Dict[str, Any]]:
        if self._exported_functions_cache is None or update_cache:
            value: List[Dict[
                str, Any]] = self._frida_rpc.enumerate_exported_functions(
                    self.main_module_name)
            exports_dict = {int(e["address"], 16): e for e in value}
            self._exported_functions_cache = exports_dict
            return exports_dict
        return self._exported_functions_cache

    def allocate_process_memory(self, size: int, near: int) -> int:
        buffer_addr = self._frida_rpc.allocate_process_memory(size, near)
        return int(buffer_addr, 16)

    def query_memory_protection(self, address: int) -> str:
        try:
            protection: str = self._frida_rpc.query_memory_protection(
                hex(address))
            return protection
        except frida.core.RPCException as rpc_exception:
            raise QueryProcessMemoryError from rpc_exception

    def set_memory_protection(self, address: int, size: int,
                              protection: str) -> bool:
        result: bool = self._frida_rpc.set_memory_protection(
            hex(address), size, protection)
        return result

    def read_process_memory(self, address: int, size: int) -> bytes:
        read_data = bytearray(size)
        try:
            for offset in range(0, size, MAX_DATA_CHUNK_SIZE):
                chunk_size = min(MAX_DATA_CHUNK_SIZE, size - offset)
                data = self._frida_rpc.read_process_memory(
                    hex(address + offset), chunk_size)
                if data is None:
                    raise ReadProcessMemoryError(
                        "read_process_memory failed (invalid parameters?)")
                read_data[offset:offset + chunk_size] = data
            return bytes(read_data)
        except frida.core.RPCException as rpc_exception:
            raise ReadProcessMemoryError from rpc_exception

    def write_process_memory(self, address: int, data: List[int]) -> None:
        try:
            self._frida_rpc.write_process_memory(hex(address), data)
        except frida.core.RPCException as rpc_exception:
            raise WriteProcessMemoryError from rpc_exception

    def terminate_process(self) -> None:
        # notify_dumping_finished takes the agent lock. A fault handler that
        # is still on that lock never returns, so kill would not run.
        try:
            frida.kill(self.pid)
        except (frida.ProcessNotFoundError, frida.InvalidOperationError):
            pass
        try:
            self._frida_session.detach()
        except (frida.InvalidOperationError, frida.ProcessNotFoundError):
            pass

    def _frida_range_to_mem_range(self, dict_range: Dict[str, Any],
                                  with_data: bool) -> MemoryRange:
        base = int(dict_range["base"], 16)
        size = dict_range["size"]
        data = None
        if with_data:
            data = self.read_process_memory(base, size)
        return MemoryRange(base=base,
                           size=size,
                           protection=dict_range["protection"],
                           data=data)


def _command_line_quotes(argument: str) -> bool:
    """Frida quotes an argv element that contains one of these."""
    return any(ch in argument for ch in (" ", "\t", "\n", "\v", "\""))


def _rundll32_entry(pe_path: Path) -> str:
    """
    First export rundll32 can call. Ordinal 0 is skipped: it is a NULL
    name to GetProcAddress, and rundll32 reports a missing entry.
    """
    ordinal = _first_export_ordinal(pe_path)
    if ordinal is None:
        return "#1"
    return "#" + str(ordinal)


def _first_export_ordinal(pe_path: Path) -> Optional[int]:
    with pe_path.open("rb") as pe_file:
        pe_file.seek(0x3C)
        e_lfanew_raw = pe_file.read(4)
        if len(e_lfanew_raw) != 4:
            return None
        e_lfanew = struct.unpack("<I", e_lfanew_raw)[0]
        pe_file.seek(e_lfanew + 6)
        number_of_sections = struct.unpack("<H", pe_file.read(2))[0]
        pe_file.seek(e_lfanew + 20)
        size_of_optional = struct.unpack("<H", pe_file.read(2))[0]
        pe_file.seek(e_lfanew + 24)
        magic = struct.unpack("<H", pe_file.read(2))[0]
        if magic == 0x10B:
            data_directory = e_lfanew + 24 + 96
        elif magic == 0x20B:
            data_directory = e_lfanew + 24 + 112
        else:
            return None

        pe_file.seek(data_directory)
        export_rva, export_size = struct.unpack("<II", pe_file.read(8))
        if export_rva == 0 or export_size == 0:
            return None

        pe_file.seek(e_lfanew + 24 + size_of_optional)
        sections = []
        for _ in range(number_of_sections):
            header = pe_file.read(40)
            if len(header) != 40:
                return None
            virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from(
                "<IIII", header, 8)
            sections.append((virtual_addr, max(virtual_size, raw_size),
                             raw_ptr, raw_size))

        def rva_to_offset(rva: int) -> Optional[int]:
            for virtual_addr, span, raw_ptr, raw_size in sections:
                if virtual_addr <= rva < virtual_addr + span:
                    delta = rva - virtual_addr
                    if delta >= raw_size:
                        return None
                    return raw_ptr + delta
            return None

        export_offset = rva_to_offset(export_rva)
        if export_offset is None:
            return None
        pe_file.seek(export_offset + 16)
        ordinal_base, number_of_functions = struct.unpack("<II",
                                                          pe_file.read(8))
        pe_file.seek(export_offset + 28)
        functions_rva = struct.unpack("<I", pe_file.read(4))[0]
        functions_offset = rva_to_offset(functions_rva)
        if functions_offset is None or number_of_functions == 0:
            return None

        pe_file.seek(functions_offset)
        for index in range(number_of_functions):
            function_raw = pe_file.read(4)
            if len(function_raw) != 4:
                return None
            function_rva = struct.unpack("<I", function_raw)[0]
            if function_rva == 0:
                continue
            ordinal = ordinal_base + index
            if ordinal == 0:
                continue
            return ordinal
    return None


def _str_to_architecture(frida_arch: str) -> Architecture:
    if frida_arch == "ia32":
        return Architecture.X86_32
    if frida_arch == "x64":
        return Architecture.X86_64
    raise ValueError


_CREATE_SUSPENDED = 0x00000004


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


def _spawn_exe_suspended(pe_path: Path) -> Tuple[int, int, int]:
    # frida.spawn debugs the new process. WinLicense treats that debug port
    # as a debugger and blocks on "A debugger has been found".
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    startup = _STARTUPINFOW()
    startup.cb = ctypes.sizeof(startup)
    created = _PROCESS_INFORMATION()
    if not kernel32.CreateProcessW(
            str(pe_path), None, None, None, False, _CREATE_SUSPENDED, None,
            str(pe_path.parent), ctypes.byref(startup), ctypes.byref(created)):
        raise OSError(ctypes.get_last_error(), "CreateProcessW failed")
    return int(created.dwProcessId), int(created.hThread), int(created.hProcess)


def _kernel32() -> ctypes.WinDLL:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _resume_suspended(thread: int, process: int) -> None:
    kernel32 = _kernel32()
    kernel32.ResumeThread(wintypes.HANDLE(thread))
    kernel32.CloseHandle(wintypes.HANDLE(thread))
    kernel32.CloseHandle(wintypes.HANDLE(process))


def _terminate_suspended(thread: int, process: int) -> None:
    kernel32 = _kernel32()
    kernel32.TerminateProcess(wintypes.HANDLE(process), 1)
    kernel32.CloseHandle(wintypes.HANDLE(thread))
    kernel32.CloseHandle(wintypes.HANDLE(process))


def spawn_and_instrument(
        pe_path: Path, text_section_ranges: List[MemoryRange],
        notify_oep_reached: OepReachedCallback) -> ProcessController:
    pid: int
    suspended_thread = 0
    suspended_process = 0
    if pe_path.suffix == ".dll":
        # rundll32 takes one "dll,entry" argument. "#0" is not an export:
        # the ordinal base is 1, and ordinal 0 is a NULL GetProcAddress name,
        # so rundll32 reported "Missing entry: #0" and returned.
        # A path Frida would quote is passed on its own so the entry stays
        # outside the quotes.
        rundll32_path = "C:\\Windows\\System32\\rundll32.exe"
        dll_path = str(pe_path.absolute())
        entry = _rundll32_entry(pe_path)
        if _command_line_quotes(dll_path):
            argv = [rundll32_path, dll_path, entry]
        else:
            argv = [rundll32_path, dll_path + "," + entry]
        pid = frida.spawn(rundll32_path, argv)
    else:
        pid, suspended_thread, suspended_process = _spawn_exe_suspended(pe_path)

    try:
        main_module_name = pe_path.name
        session = frida.attach(pid)
        frida_js = resources.open_text("unlicense.resources", "frida.js").read()
        script = session.create_script(frida_js)
        on_message_callback = functools.partial(_frida_callback,
                                                notify_oep_reached)
        script.on('message', on_message_callback)
        script.load()

        frida_rpc = script.exports
        process_controller = FridaProcessController(pid, main_module_name,
                                                    session, script)

        def _on_detached(reason: str, _crash: Any) -> None:
            if reason == "process-terminated":
                process_controller.process_exited.set()

        session.on("detached", _on_detached)
        frida_rpc.setup_oep_tracing(pe_path.name, [[r.base, r.size]
                                                   for r in text_section_ranges])
        if suspended_thread == 0:
            frida.resume(pid)
        else:
            _resume_suspended(suspended_thread, suspended_process)
            suspended_thread = 0
            suspended_process = 0
    except Exception:
        if suspended_process != 0:
            _terminate_suspended(suspended_thread, suspended_process)
        raise

    return process_controller


def _frida_callback(notify_oep_reached: OepReachedCallback,
                    message: Dict[str, Any], _data: Any) -> None:
    msg_type = message['type']
    if msg_type == 'error':
        LOG.error(message)
        LOG.error(message['stack'])
        return

    if msg_type == 'send':
        payload = message['payload']
        event = payload.get('event', '')
        if event == 'oep_reached':
            # Note: We cannot use RPCs in `on_message` callbacks, so we have to
            # delay the actual dumping.
            notify_oep_reached(int(payload['BASE'],
                                   16), int(payload['OEP'], 16),
                               bool(payload['DOTNET']))
            return

    raise NotImplementedError('Unknown message received')
