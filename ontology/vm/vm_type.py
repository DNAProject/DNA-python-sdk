#
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright 2019 DNA Dev team
#
"""
Copyright (C) 2018 The ontology Authors
This file is part of The ontology library.

The ontology is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

The ontology is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
"""

from enum import IntEnum, unique

from ontology.exception.error_code import ErrorCode

from ontology.exception.exception import SDKException


@unique
class VmType(IntEnum):
    Neo = 1
    Wasm = 3

    @classmethod
    def from_int(cls, value: int):
        if value == 1:
            return cls.Neo
        if value == 3:
            return cls.Wasm
        raise SDKException(ErrorCode.unknown_vm_type)
