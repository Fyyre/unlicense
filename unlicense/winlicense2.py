import logging
import struct
from bisect import bisect_right
from typing import Dict, List, Optional, Tuple, Any

from capstone import (  # type: ignore
    Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64)

from .imports import ImportToCallSiteDict, WrapperSet, find_wrapped_imports
from .dump_utils import dump_pe, pointer_size_to_fmt
from .emulation import resolve_wrapped_api
from .function_hashing import compute_function_hash, EMPTY_FUNCTION_HASH
from .process_control import (ProcessController, Architecture, MemoryRange,
                              ReadProcessMemoryError, WriteProcessMemoryError)

LOG = logging.getLogger(__name__)


def fix_and_dump_pe(process_controller: ProcessController, pe_file_path: str,
                    image_base: int, oep: int,
                    text_section_range: MemoryRange) -> None:
    """
    Main dumping routine for Themida/WinLicense 2.x.
    """
    # Convert RVA range to VA range
    section_virtual_addr = image_base + text_section_range.base
    text_section_range = MemoryRange(
        section_virtual_addr, text_section_range.size, "r-x",
        process_controller.read_process_memory(section_virtual_addr,
                                               text_section_range.size))
    assert text_section_range.data is not None
    LOG.debug(".text section: %s", str(text_section_range))

    arch = process_controller.architecture
    exports_dict = process_controller.enumerate_exported_functions()

    # Instanciate the disassembler
    if arch == Architecture.X86_32:
        cs_mode = CS_MODE_32
    elif arch == Architecture.X86_64:
        cs_mode = CS_MODE_64
    else:
        raise NotImplementedError(f"Unsupported architecture: {arch}")
    md = Cs(CS_ARCH_X86, cs_mode)
    md.detail = True

    LOG.info("Looking for wrapped imports ...")
    api_to_calls, wrapper_set = find_wrapped_imports(text_section_range,
                                                     exports_dict, md,
                                                     process_controller)

    LOG.info("Potential import wrappers found: %d", len(wrapper_set))
    export_hashes = None
    # Hash-matching strategy is only needed for 32-bit PEs
    if arch == Architecture.X86_32:
        LOG.info("Generating exports' hashes, this might take some time ...")
        export_hashes = _generate_export_hashes(md, exports_dict,
                                                process_controller)

    LOG.info("Resolving imports ...")
    wrapper_to_api = _resolve_imports(api_to_calls, wrapper_set, export_hashes,
                                      md, process_controller)
    LOG.info("Imports resolved: %d", len(api_to_calls))

    _collect_pointer_table_imports(api_to_calls, wrapper_to_api, exports_dict,
                                   image_base, process_controller)
    LOG.info("Imports including pointer tables: %d", len(api_to_calls))

    iat_addr, iat_size = _generate_new_iat_in_process(api_to_calls,
                                                      text_section_range.base,
                                                      process_controller)
    LOG.info("Generated the fake IAT at %s, size=%s", hex(iat_addr),
             hex(iat_size))

    # Ensure the range is writable
    process_controller.set_memory_protection(text_section_range.base,
                                             text_section_range.size, "rwx")
    # Replace detected references to wrappers or imports
    LOG.info("Patching call and jmp sites ...")
    _fix_import_references_in_process(api_to_calls, iat_addr,
                                      process_controller)
    _redirect_stored_import_pointers(api_to_calls, wrapper_to_api, iat_addr,
                                     image_base, oep, pe_file_path,
                                     process_controller)
    # Restore memory protection to RX
    process_controller.set_memory_protection(text_section_range.base,
                                             text_section_range.size, "r-x")

    LOG.info("Dumping PE with OEP=%s ...", hex(oep))
    dump_pe(process_controller, pe_file_path, image_base, oep, iat_addr,
            iat_size, True)


def _generate_export_hashes(
        md: Cs, exports_dict: Dict[int, Dict[str, Any]],
        process_controller: ProcessController) -> Dict[int, int]:
    """
    Go through the given export dictionary and produce a hash for each function
    listed in it.
    """
    result = {}
    modules = process_controller.enumerate_modules()
    LOG.debug("Hashing exports for %s", str(modules))
    ranges = []
    for module_name in modules:
        if module_name != process_controller.main_module_name:
            ranges += process_controller.enumerate_module_ranges(
                module_name, include_data=True)
    ranges = list(
        filter(lambda mem_range: mem_range.protection[2] == 'x', ranges))

    def get_data(addr: int, size: int) -> bytes:
        for mem_range in ranges:
            if mem_range.data is None:
                continue
            if mem_range.contains(addr):
                offset = addr - mem_range.base
                return mem_range.data[offset:offset + size]
        return bytes()

    exports_count = len(exports_dict)
    for i, (export_addr, _) in enumerate(exports_dict.items()):
        export_hash = compute_function_hash(md, export_addr, get_data,
                                            process_controller)
        if export_hash != EMPTY_FUNCTION_HASH:
            result[export_hash] = export_addr
        else:
            LOG.debug("Empty hash for %s", hex(export_addr))
        LOG.debug("Exports hashed: %d/%d", i, exports_count)

    return result


def _resolve_imports(api_to_calls: ImportToCallSiteDict,
                     wrapper_set: WrapperSet,
                     export_hashes: Optional[Dict[int, int]], md: Cs,
                     process_controller: ProcessController) -> Dict[int, int]:
    """
    Resolve potential import wrappers by hash-matching or emulation.
    Returns a map of wrapper address to resolved export address.
    """
    arch = process_controller.architecture
    page_size = process_controller.page_size

    def get_data(addr: int, size: int) -> bytes:
        try:
            return process_controller.read_process_memory(addr, size)
        except ReadProcessMemoryError:
            # In case we crossed a page boundary and tried to read an invalid
            # page, reduce size to stop at page boundary, and try again.
            size = page_size - (addr % page_size)
        return process_controller.read_process_memory(addr, size)

    # Iterate over the set of potential import wrappers and try to resolve them
    resolved_wrappers: Dict[int, int] = {}
    problematic_wrappers = set()
    for call_addr, call_size, instr_was_jmp, wrapper_addr, _ in wrapper_set:
        resolved_addr = resolved_wrappers.get(wrapper_addr)
        if resolved_addr is not None:
            LOG.debug("Already resolved wrapper: %s -> %s", hex(wrapper_addr),
                      hex(resolved_addr))
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
            continue

        if wrapper_addr in problematic_wrappers:
            # Already failed to resolve this one, ignore
            LOG.debug("Skipping unresolved wrapper")
            continue

        # If 32-bit executable, try hash-matching
        if export_hashes is not None and arch == Architecture.X86_32:
            try:
                import_hash = compute_function_hash(md, wrapper_addr, get_data,
                                                    process_controller)
            except Exception as ex:
                LOG.debug("Failure for wrapper at %s: %s", hex(wrapper_addr),
                          str(ex))
                problematic_wrappers.add(wrapper_addr)
                continue
            if import_hash != EMPTY_FUNCTION_HASH:
                LOG.debug("Hash: %s", hex(import_hash))
                resolved_addr = export_hashes.get(import_hash)
                if resolved_addr is not None:
                    LOG.debug("Hash matched")
                    LOG.debug("Resolved API: %s -> %s", hex(wrapper_addr),
                              hex(resolved_addr))
                    resolved_wrappers[wrapper_addr] = resolved_addr
                    api_to_calls[resolved_addr].append(
                        (call_addr, call_size, instr_was_jmp))
                    continue

        # Try to resolve the destination address by emulating the wrapper
        resolved_addr = resolve_wrapped_api(call_addr, process_controller,
                                            call_addr + call_size)
        if resolved_addr is not None:
            LOG.debug("Resolved API: %s -> %s", hex(wrapper_addr),
                      hex(resolved_addr))
            resolved_wrappers[wrapper_addr] = resolved_addr
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
        else:
            problematic_wrappers.add(wrapper_addr)

    return resolved_wrappers


def _collect_pointer_table_imports(
        api_to_calls: ImportToCallSiteDict, wrapper_to_api: Dict[int, int],
        exports_dict: Dict[int, Dict[str, Any]], image_base: int,
        process_controller: ProcessController) -> None:
    """
    Themida 2.x keeps a table of direct pointers at its runtime import stubs.
    Those stubs live in a private allocation and are not part of the image, so
    a dump crashes on the first indirect call through the table.
    """
    known = dict(wrapper_to_api)
    for api_addr in api_to_calls:
        known[api_addr] = api_addr

    image_end = image_base
    chunks: List[Tuple[int, bytes]] = []
    for mem_range in process_controller.main_module_ranges:
        image_end = max(image_end, mem_range.base + mem_range.size)
        try:
            raw = process_controller.read_process_memory(mem_range.base,
                                                         mem_range.size)
        except ReadProcessMemoryError:
            continue
        chunks.append((mem_range.base, raw))

    ptr_size = process_controller.pointer_size
    ptr_fmt = pointer_size_to_fmt(ptr_size)
    seeds = _slots_matching(chunks, ptr_size, ptr_fmt, set(known))
    resolved_slots = {addr for addr, _ in seeds}
    added = 0
    for _ in range(8):
        nearby = _slots_near(chunks, ptr_size, ptr_fmt, sorted(resolved_slots),
                             0x14)
        grew = False
        seen_values = set()
        for slot_addr, value in nearby:
            if slot_addr in resolved_slots or value in seen_values:
                continue
            if image_base <= value < image_end or value < 0x10000:
                continue
            seen_values.add(value)
            api_addr = known.get(value)
            if api_addr is None:
                api_addr = _resolve_stub_pointer(value, exports_dict,
                                                 process_controller)
            if api_addr is None or api_addr not in exports_dict:
                continue
            known[value] = api_addr
            resolved_slots.add(slot_addr)
            if api_addr not in api_to_calls:
                api_to_calls[api_addr] = []
                added += 1
            grew = True
        if not grew:
            break

    # Remember newly discovered stub addresses for the later rewrite.
    wrapper_to_api.update(
        {value: api for value, api in known.items() if value != api})
    LOG.info("Pointer-table imports added: %d", added)


def _slots_matching(chunks: List[Tuple[int, bytes]], ptr_size: int,
                    ptr_fmt: str,
                    values: set) -> List[Tuple[int, int]]:
    found = []
    for base, raw in chunks:
        limit = len(raw) - ptr_size + 1
        for offset in range(0, limit, ptr_size):
            value = struct.unpack_from(ptr_fmt, raw, offset)[0]
            if value in values:
                found.append((base + offset, value))
    return found


def _slots_near(chunks: List[Tuple[int, bytes]], ptr_size: int, ptr_fmt: str,
                sorted_slots: List[int],
                window: int) -> List[Tuple[int, int]]:
    found = []
    if not sorted_slots:
        return found
    for base, raw in chunks:
        limit = len(raw) - ptr_size + 1
        for offset in range(0, limit, ptr_size):
            slot_addr = base + offset
            index = bisect_right(sorted_slots, slot_addr)
            near = False
            if index < len(sorted_slots) and sorted_slots[
                    index] - slot_addr <= window:
                near = True
            if index > 0 and slot_addr - sorted_slots[index - 1] <= window:
                near = True
            if not near:
                continue
            value = struct.unpack_from(ptr_fmt, raw, offset)[0]
            found.append((slot_addr, value))
    return found


def _resolve_stub_pointer(
        stub_addr: int, exports_dict: Dict[int, Dict[str, Any]],
        process_controller: ProcessController) -> Optional[int]:
    ptr_size = process_controller.pointer_size
    ptr_fmt = pointer_size_to_fmt(ptr_size)
    try:
        raw = process_controller.read_process_memory(stub_addr, 8)
    except ReadProcessMemoryError:
        return None

    api_addr = None
    if ptr_size == 4 and raw[:2] == b"\xff\x25":
        slot_addr = struct.unpack_from("<I", raw, 2)[0]
        try:
            api_addr = struct.unpack(
                ptr_fmt,
                process_controller.read_process_memory(slot_addr,
                                                       ptr_size))[0]
        except ReadProcessMemoryError:
            api_addr = None
    elif ptr_size == 4 and raw[0] == 0xB8 and raw[5:7] == b"\xff\xe0":
        api_addr = struct.unpack_from("<I", raw, 1)[0]

    if api_addr in exports_dict:
        return api_addr

    emulated = resolve_wrapped_api(stub_addr, process_controller)
    if emulated in exports_dict:
        return emulated
    return None


def _redirect_stored_import_pointers(
        api_to_calls: ImportToCallSiteDict, wrapper_to_api: Dict[int, int],
        iat_addr: int, image_base: int, oep: int, pe_file_path: str,
        process_controller: ProcessController) -> None:
    """
    Point stored wrapper/API addresses at in-image jump stubs. The stubs go
    through the IAT, so the dump does not depend on Themida's private
    allocation or on the system DLLs' load addresses.
    """
    ptr_size = process_controller.pointer_size
    arch = process_controller.architecture
    stub_stride = 8
    stub_bytes_len = len(api_to_calls) * stub_stride
    cave_addr = _claim_import_stub_cave(process_controller, image_base, oep,
                                        pe_file_path, stub_bytes_len)
    if cave_addr is None or stub_bytes_len == 0:
        LOG.info("No cave for import stubs, leaving stored pointers")
        return
    LOG.info("Import stub cave at %s", hex(cave_addr))

    value_to_stub: Dict[int, int] = {}
    blob = bytearray()
    for index, api_addr in enumerate(api_to_calls):
        stub_addr = cave_addr + index * stub_stride
        iat_slot = iat_addr + index * ptr_size
        value_to_stub[api_addr] = stub_addr
        if arch == Architecture.X86_32:
            insn = bytes([0xFF, 0x25]) + struct.pack("<I", iat_slot)
        elif arch == Architecture.X86_64:
            disp = iat_slot - (stub_addr + 6)
            insn = bytes([0xFF, 0x25]) + struct.pack("<i", disp)
        else:
            raise NotImplementedError(f"Unsupported architecture: {arch}")
        blob += insn + b"\x90" * (stub_stride - len(insn))
    try:
        process_controller.write_process_memory(cave_addr, list(blob))
    except WriteProcessMemoryError:
        LOG.info("Failed to write import stubs, leaving stored pointers")
        return

    for wrapper_addr, api_addr in wrapper_to_api.items():
        stub_addr = value_to_stub.get(api_addr)
        if stub_addr is not None:
            value_to_stub[wrapper_addr] = stub_addr

    ptr_fmt = pointer_size_to_fmt(ptr_size)
    rewritten = 0
    for mem_range in process_controller.main_module_ranges:
        if cave_addr <= mem_range.base < cave_addr + stub_bytes_len:
            continue
        try:
            raw = process_controller.read_process_memory(mem_range.base,
                                                         mem_range.size)
        except ReadProcessMemoryError:
            continue
        limit = len(raw) - ptr_size + 1
        for offset in range(0, limit, ptr_size):
            value = struct.unpack_from(ptr_fmt, raw, offset)[0]
            stub_addr = value_to_stub.get(value)
            if stub_addr is None or stub_addr == value:
                continue
            slot_addr = mem_range.base + offset
            if iat_addr <= slot_addr < iat_addr + len(api_to_calls) * ptr_size:
                continue
            _write_pointer(process_controller, slot_addr, stub_addr, ptr_fmt)
            rewritten += 1

    LOG.info("Redirected stored import pointers: %d", rewritten)


def _claim_import_stub_cave(process_controller: ProcessController,
                            image_base: int, oep: int, pe_file_path: str,
                            size: int) -> Optional[int]:
    """
    Themida's entry section is a usable cave, but after unpacking it may be
    unreadable or split into ranges smaller than the stub block. Take the
    cave from the on-disk section table and make it writable.
    """
    if size <= 0:
        return None

    for candidate in _import_stub_caves(image_base, oep, pe_file_path, size):
        try:
            if process_controller.set_memory_protection(candidate, size,
                                                        "rwx"):
                return candidate
        except Exception as ex:
            LOG.debug("Import stub cave %s rejected: %s", hex(candidate), ex)
    return None


def _import_stub_caves(image_base: int, oep: int, pe_file_path: str,
                       size: int) -> List[int]:
    with open(pe_file_path, "rb") as pe_file:
        pe_file.seek(0x3C)
        e_lfanew = struct.unpack("<I", pe_file.read(4))[0]
        pe_file.seek(e_lfanew + 6)
        number_of_sections = struct.unpack("<H", pe_file.read(2))[0]
        pe_file.seek(e_lfanew + 20)
        size_of_optional = struct.unpack("<H", pe_file.read(2))[0]
        pe_file.seek(e_lfanew + 24 + 16)
        ep_rva = struct.unpack("<I", pe_file.read(4))[0]
        pe_file.seek(e_lfanew + 24 + size_of_optional)
        sections = []
        for _ in range(number_of_sections):
            header = pe_file.read(40)
            virtual_size, virtual_addr = struct.unpack_from("<II", header, 8)
            characteristics = struct.unpack_from("<I", header, 36)[0]
            sections.append((virtual_addr, virtual_size, characteristics))

    oep_rva = oep - image_base
    ranked = []
    for virtual_addr, virtual_size, characteristics in sections:
        if virtual_size < size:
            continue
        if virtual_addr <= oep_rva < virtual_addr + virtual_size:
            continue
        holds_entry = virtual_addr <= ep_rva < virtual_addr + virtual_size
        executable = (characteristics & 0x20000000) != 0
        ranked.append((holds_entry, executable, virtual_addr))

    ranked.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    return [image_base + virtual_addr for _, _, virtual_addr in ranked]


def _write_pointer(process_controller: ProcessController, addr: int,
                   value: int, ptr_fmt: str) -> None:
    data = list(struct.pack(ptr_fmt, value))
    try:
        process_controller.write_process_memory(addr, data)
    except WriteProcessMemoryError:
        process_controller.set_memory_protection(addr,
                                                 process_controller.page_size,
                                                 "rwx")
        process_controller.write_process_memory(addr, data)


def _generate_new_iat_in_process(
        imports_dict: ImportToCallSiteDict, near_to_ptr: int,
        process_controller: ProcessController) -> Tuple[int, int]:
    """
    Generate a new IAT from a list of imported function addresses and write
    it into a new buffer into the target process. `near_to_ptr` is used to
    allocate the new IAT near the unpacked module (which is needed for 64-bit
    processes).
    """
    ptr_size = process_controller.pointer_size
    ptr_format = pointer_size_to_fmt(ptr_size)
    iat_size = len(imports_dict) * ptr_size
    # Allocate a new buffer in the target process
    iat_addr = process_controller.allocate_process_memory(
        iat_size, near_to_ptr)

    # Generate the new IAT and write it into the buffer
    new_iat_data = bytearray()
    for import_addr in imports_dict:
        new_iat_data += struct.pack(ptr_format, import_addr)
    process_controller.write_process_memory(iat_addr, list(new_iat_data))

    return iat_addr, iat_size


def _fix_import_references_in_process(
        api_to_calls: ImportToCallSiteDict, iat_addr: int,
        process_controller: ProcessController) -> None:
    """
    Replace resolved wrapper call sites with call/jmp to the new IAT (that
    contains resolved imports).
    """
    arch = process_controller.architecture
    ptr_size = process_controller.pointer_size

    for i, call_addrs in enumerate(api_to_calls.values()):
        for call_addr, _, instr_was_jmp in call_addrs:
            if arch == Architecture.X86_32:
                # Absolute
                operand = iat_addr + i * ptr_size
                fmt = "<I"
            elif arch == Architecture.X86_64:
                # RIP-relative
                operand = iat_addr + i * ptr_size - (call_addr + 6)
                fmt = "<i"
            else:
                raise NotImplementedError(f"Unsupported architecture: {arch}")

            if instr_was_jmp:
                # jmp [iat_addr + i * ptr_size]
                new_instr = bytes([0xFF, 0x25]) + struct.pack(fmt, operand)
            else:
                # call [iat_addr + i * ptr_size]
                new_instr = bytes([0xFF, 0x15]) + struct.pack(fmt, operand)
            process_controller.write_process_memory(call_addr, list(new_instr))
