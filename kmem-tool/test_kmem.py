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
# limitations under the Lice

import unittest
from unittest import mock
import logging
import re
import sys

import kmem as swut
import capdl  # pylint: disable=import-error
from capdl.Object import ObjectType  # pylint: disable=import-error

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FileProxy(object):

    def __init__(self, real_obj):
        self._real_obj = real_obj
        self.write_log = ""

    def __getattr__(self, name):
        logger.debug("__getattr__: name = %s", name)
        return getattr(self._real_obj, name)

    def write(self, *args, **kwargs):
        logger.debug("write: args = %s", args)
        logger.debug("write: kwargs = %s", kwargs)
        self.write_log += args[0]
        return self._real_obj.write(*args, **kwargs)


class KmemTests(unittest.TestCase):

    def test_single_component_single_frame(self):
        sys.argv = ["", "--object-state", "/dev/null", "--details"]

        proxy_stdout = FileProxy(sys.stdout)
        with mock.patch("builtins.open"), \
                mock.patch("pickle.load") as pickle_mock, \
                mock.patch("sys.stdout", proxy_stdout):
            obj_space = capdl.Allocator.ObjectAllocator()
            obj_space.alloc(ObjectType.seL4_FrameObject,
                            name="test_frame_name")
            state = capdl.Allocator.AllocatorState(obj_space)
            pickle_mock.return_value = state
            swut.main()

        self.assertIsNotNone(
            re.search(r"test_frame_name.*4 KiB.*4096", proxy_stdout.write_log))
        self.assertIsNotNone(
            re.search(r"GRAND TOTAL.*4 KiB.*4096", proxy_stdout.write_log))


if __name__ == "__main__":
    unittest.main()
