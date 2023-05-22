# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import enum
import logging
import pickle
import re
import sys
from typing import Dict, List, Optional

try:
    import capdl  # pylint: disable=unused-import
except ModuleNotFoundError as e:
    e.msg += (". The PYTHONPATH environment variable should include the path"
              "to the CAPDL module "
              "($ROOTDIR/cantrip/projects/capdl/python-capdl-tool)")
    raise

from capdl.Object import Frame, register_object_sizes  # pylint: disable=import-error

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# TODO(sleffler): does pickle have target cpu?
riscv32_object_sizes = {
    'seL4_TCBObject': 9,
    'seL4_RTReplyObject': 4,
    'seL4_EndpointObject': 4,
    'seL4_NotificationObject': 5,  # MCS, !MCS = 4
    'seL4_SmallPageObject': 12,
    'seL4_LargePageObject': 22,
    'seL4_ASID_Pool': 12,
    'seL4_Slot': 4,
    'seL4_PageTableObject': 12,
    'seL4_PageDirectoryObject': 12,
}

def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--object-state',
                        type=argparse.FileType('rb'),
                        required=True,
                        help='''The allocator state exported from
                        capdl_linker.py
                        The file is generated as part of the cantrip build
                        process.
                        ''')
    parser.add_argument('--kernel',
                        default=False,
                        action='store_true',
                        help='''Include kernel data structures in analysis.''')
    parser.add_argument('--details',
                        default=False,
                        action='store_true',
                        help='''Change the output format to have a per frame
                        type breakdown.''')
    parser.add_argument('--verbose',
                        default=False,
                        action='store_true',
                        help='''Enable messages during analysis phase.''')

    args = parser.parse_args()

    allocator_state = pickle.load(args.object_state)

    register_object_sizes(riscv32_object_sizes)

    sizes = accumulate_obj_sizes(allocator_state,
                                 kernel=args.kernel,
                                 verbose=args.verbose)
    print_summary(sizes, details=args.details)

    return 0


class FrameType(enum.Enum):
    ELF = enum.auto()
    BSS = enum.auto()
    IPC_BUFFER = enum.auto()
    STACK = enum.auto()
    COPYREGION = enum.auto()
    BOOTINFO = enum.auto()
    MMIO = enum.auto()


def accumulate_obj_sizes(allocator_state, kernel=False, verbose=False) -> Dict:
    ret_sizes = {}
    for component in allocator_state.obj_space.labels.keys():
        for obj in allocator_state.obj_space.labels.get(component):
            if component is None:
                # e.g. BOOTINFO_FRAME
                if verbose:
                    print("SKIP", obj.name)
                continue
            component_name = component

            if isinstance(obj, Frame):
                # Page frame object
                ft = frame_type(obj.name, obj.fill, obj.paddr)
                if ft == FrameType.COPYREGION:
                    # NB: for C templates, Rust templates have no backing frames
                    component_name = get_copy_region_component(obj.name)
                obj_name = ft
                size = obj.size
            else:
                # seL4 kernel object
                if not kernel:
                    continue
                obj_name = obj.name

                size = obj.get_size_bits()
                if size is None:
                    if verbose:
                        print("SKIP", obj.name)
                    continue
                size = 1 << size

            if component_name not in ret_sizes:
                ret_sizes[component_name] = {}
            if obj_name not in ret_sizes[component_name]:
                ret_sizes[component_name][obj_name] = 0
            ret_sizes[component_name][obj_name] += size
    return ret_sizes


def print_summary(sizes: Dict, details=False) -> None:
    col_widths = (
        25,  # component name
        28,  # object type
        12,  # size in KiB
        20,  # size in bytes
    )
    grand_total = 0
    for component_name in sorted(list(sizes.keys())):
        total = sum(list(sizes[component_name].values()))

        # MMIO is mapped but doesn't use physical memory
        total -= sizes[component_name].get(FrameType.MMIO, 0)

        # Copy Regions are immidately freed to create a hole in virtual memory
        total -= sizes[component_name].get(FrameType.COPYREGION, 0)

        if total == 0 and not details:
            continue

        grand_total += total
        print(
            pad_right(component_name, col_widths[0]) +
            pad_right("", col_widths[1]) +
            pad_left(f"{to_kib(total)} KiB", col_widths[2]) +
            pad_left(str(total), col_widths[3]))
        if details:
            for key, size in sizes[component_name].items():
                obj_name = str(key)
                while obj_name.startswith(component_name + '_'):
                    obj_name = obj_name[len(component_name) + 1:]
                print(
                    pad_right("", col_widths[0]) +
                    pad_right(str(obj_name), col_widths[1]) +
                    pad_left(f"{to_kib(size)} KiB", col_widths[2]) +
                    pad_left(str(size), col_widths[3]))
    print(
        pad_right("GRAND TOTAL", col_widths[0]) +
        pad_right("", col_widths[1]) +
        pad_left(f"{to_kib(grand_total)} KiB", col_widths[2]) +
        pad_left(str(grand_total), col_widths[3]))


def frame_type(frame_name: str, fill: List[str],
               paddr: Optional[int]) -> FrameType:
    assert len(fill) in (
        0,
        1,
    )
    if "_copy_region_" in frame_name:
        return FrameType.COPYREGION
    if "_frame__camkes_ipc_buffer_" in frame_name:
        return FrameType.IPC_BUFFER
    if frame_name.startswith("stack__camkes_stack_"):
        return FrameType.STACK
    if fill and "CDL_FrameFill_BootInfo" in fill[0]:
        return FrameType.BOOTINFO
    if fill and "CDL_FrameFill_FileData" in fill[0]:
        return FrameType.ELF
    if re.search(r"_data_[0-9]_obj", frame_name):
        if paddr:
            return FrameType.MMIO
        return FrameType.BSS
    if paddr:
        return FrameType.MMIO
    return FrameType.BSS


def get_copy_region_component(frame_name: str) -> str:
    return re.sub(r"_copy_region.*", "", frame_name)


def to_kib(byte_count: int) -> int:
    if 0 < byte_count < (1 << 10):
        return 1
    return byte_count >> 10


def pad_right(string: str, length: int) -> str:
    return string + " " * (length - len(string))


def pad_left(string: str, length: int) -> str:
    return " " * (length - len(string)) + string


if __name__ == '__main__':
    sys.exit(main())
