#
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright 2019 DNA Dev team
#
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

from os import path, environ

from dna.exception.exception import SDKException
from dna.sdk import DNA

sdk = DNA()
sdk.rpc.connect_to_localhost()
sdk.aio_rpc.connect_to_localhost()
sdk.restful.connect_to_localhost()
sdk.aio_restful.connect_to_localhost()
sdk.websocket.connect_to_localhost()

password = '1'
wallet_path = path.join(path.dirname(__file__), 'test_wallet.json')
wallet_manager = sdk.wallet_manager
wallet_manager.open_wallet(wallet_path, is_create=False)
acct1 = wallet_manager.get_account_by_b58_address('AXEcztb3H4LuSkMDFhRZA3QaNaPq23tThn', password)
acct2 = wallet_manager.get_account_by_b58_address('AT32a8j6MCD8NRfLerw2mhUQ68CfJwHwCH', password)
acct3 = wallet_manager.get_account_by_b58_address('AJkgPMUNBvQxm7V1mRRRLBRKT35vzDXwTc', password)
acct4 = wallet_manager.get_account_by_b58_address('AZcb4gtuUNyZyBwQNn3ZZASNkR63Z3437r', password)
ont_id_1 = 'did:dna:TVzQu3LvZiDbZQkAGewnGpzctrdmSg41Ct'
identity1 = wallet_manager.get_identity_by_ont_id(ont_id_1)
identity1_ctrl_acct = wallet_manager.get_control_account_by_index(ont_id_1, 0, password)
ont_id_2 = 'did:dna:TTrL48YuxBuqvddCJmstCEty7ubaa4wVdz'
identity2 = wallet_manager.get_identity_by_ont_id(ont_id_2)
identity2_ctrl_acct = wallet_manager.get_control_account_by_index(ont_id_2, 0, password)
wallet_manager.save()

not_panic = ['balance insufficient', 'ConnectionError', 'unknown transaction', 'Notify not found in {}']


def not_panic_exception(func):
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except SDKException as e:
            if not any(x in e.args[1] for x in not_panic):
                raise e

    return wrapper
