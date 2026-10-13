from typing import Any, Iterator
import lief


# Note(ergrelet): this wrapper is a workaround for some bug in LIEF. We're not
# iterating directly on `binary.sections` because it seems LIEF crashes for some
# unkown reasons on certain executables
def lief_pe_sections(binary: lief.PE.Binary) -> Iterator[lief.PE.Section]:
    num_of_sections = len(binary.sections)
    for i in range(num_of_sections):
        yield binary.sections[i]


# Note(ergrelet): same as above
def lief_pe_data_directories(
        binary: lief.PE.Binary) -> Iterator[lief.PE.DataDirectory]:
    num_of_data_dirs = len(binary.data_directories)
    for i in range(num_of_data_dirs):
        yield binary.data_directories[i]


# LIEF 1.0 moved these enums off lief.PE. 0.13 still exposes them there.
def section_mem_execute() -> Any:
    if hasattr(lief.PE, "SECTION_CHARACTERISTICS"):
        return lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
    return lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE


def header_relocs_stripped() -> Any:
    if hasattr(lief.PE, "HEADER_CHARACTERISTICS"):
        return lief.PE.HEADER_CHARACTERISTICS.RELOCS_STRIPPED
    return lief.PE.Header.CHARACTERISTICS.RELOCS_STRIPPED


def dll_dynamic_base() -> Any:
    if hasattr(lief.PE, "DLL_CHARACTERISTICS"):
        return lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
    return lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE


def data_directory_resource_table() -> Any:
    if hasattr(lief.PE, "DATA_DIRECTORY"):
        return lief.PE.DATA_DIRECTORY.RESOURCE_TABLE
    return lief.PE.DataDirectory.TYPES.RESOURCE_TABLE


def section_name_str(section: lief.PE.Section) -> str:
    # 1.0 returns bytes. 0.13 returns str.
    name = section.fullname
    if isinstance(name, (bytes, bytearray)):
        name = bytes(name).split(b"\x00", 1)[0].decode("ascii", "ignore")
    return name


def write_rebuilt_pe(binary: lief.PE.Binary, output_file_path: str) -> None:
    # 1.0 takes a config object. dos_stub and overlay default to true there,
    # but 0.13 only keeps them when the setters are called.
    if hasattr(lief.PE.Builder, "build_dos_stub"):
        builder = lief.PE.Builder(binary)
        builder.build_dos_stub(True)
        builder.build_overlay(True)
        builder.build()
        builder.write(output_file_path)
        return

    config = lief.PE.Builder.config_t()
    config.dos_stub = True
    config.overlay = True
    builder = lief.PE.Builder(binary, config)
    builder.build()
    builder.write(output_file_path)