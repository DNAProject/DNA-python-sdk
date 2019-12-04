#
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright 2019 DNA Dev team
#
"""
Copyright (C) 2018-2019 The ontology Authors
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

from ontology.vm.build_params import BuildParams
from ontology.core.base_invoke_func import BaseInvokeFunc


class NeoInvokeFunction(BaseInvokeFunc):
    def __init__(self, func_name: str, parameters: list = None, return_type: str = ''):
        super().__init__(func_name, parameters, return_type)

    def create_invoke_code(self):
        param_list = list()
        param_list.append(self.func_name.encode('utf-8'))
        param_list.append(self.parameters)
        return BuildParams.create_neo_vm_invoke_code(param_list)

