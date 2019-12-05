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

import asyncio
import unittest

from Cryptodome.Random.random import randint

from dna.sdk import Ontology
from tests import sdk, acct2, acct3, acct4, password, not_panic_exception

from dna.utils import utils
from dna.crypto.curve import Curve
from dna.utils.neo import NeoData
from dna.utils.event import Event
from dna.account.account import Account
from dna.crypto.signature import Signature
from dna.exception.exception import SDKException
from dna.crypto.signature_scheme import SignatureScheme
from dna.contract.native.did import Attribute


class TestAioDID(unittest.TestCase):
    def setUp(self):
        self.gas_price = 500
        self.gas_limit = 20000

    def check_ecdsa_pk(self, did: str, pk: dict):
        self.assertIn(did, pk['PubKeyId'])
        self.assertEqual('ECDSA', pk['Type'])
        self.assertEqual('P256', pk['Curve'])
        self.assertEqual(66, len(pk['Value']))

    async def check_pk_by_did(self, did):
        pub_keys = await sdk.native_vm.aio_did().get_public_keys(did)
        for pk in pub_keys:
            self.check_ecdsa_pk(did, pk)

    async def get_ddo_test_case(self, did: str):
        ddo = await sdk.native_vm.aio_did().get_ddo(did)
        for pk in ddo.get('Owners', list()):
            self.check_ecdsa_pk(did, pk)
        self.assertEqual(did, ddo.get('DID', ''))

    @not_panic_exception
    @DNA.runner
    async def test_get_public_keys(self):
        did_list = ['did:dna:APywVQ2UKBtitqqJQ9JrpNeY8VFAnrZXiR', 'did:dna:ANDfjwrUroaVtvBguDtrWKRMyxFwvVwnZD']
        for did in did_list:
            await self.check_pk_by_did(did)
        try:
            sdk.default_aio_network.connect_to_main_net()
            did = 'did:dna:ATZhaVirdEYkpsHQDn9PMt5kDCq1VPHcTr'
            await self.check_pk_by_did(did)
        finally:
            sdk.default_aio_network.connect_to_localhost()

    @not_panic_exception
    @DNA.runner
    async def test_get_ddo(self):
        did = 'did:dna:AazEvfQPcQ2GEFFPLF1ZLwQ7K5jDn81hve'
        try:
            await self.get_ddo_test_case(did)
        finally:
            sdk.default_aio_network.connect_to_localhost()
        try:
            sdk.default_aio_network.connect_to_main_net()
            did = 'did:dna:AP8n55wdQCRePFiNiR4kobGBhvBCMkVPun'
            await self.get_ddo_test_case(did)
        finally:
            sdk.default_aio_network.connect_to_localhost()

    @not_panic_exception
    @DNA.runner
    async def test_registry_did(self):
        did = sdk.native_vm.aio_did()
        try:
            identity = sdk.wallet_manager.create_identity(password)
            ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        except SDKException as e:
            self.assertIn('Wallet identity exists', e.args[1])
            return
        try:
            await did.registry_did(identity.did, ctrl_acct, acct2, self.gas_price, self.gas_limit)
        except SDKException as e:
            if 'already registered' not in e.args[1]:
                raise e

    async def check_register_did_event(self, did: str, tx_hash: str):
        self.assertEqual(64, len(tx_hash))
        await asyncio.sleep(randint(10, 15))
        event = await sdk.default_aio_network.get_contract_event_by_tx_hash(tx_hash)
        hex_contract_address = sdk.native_vm.aio_did().contract_address
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('Register', notify['States'][0])
        self.assertEqual(did, notify['States'][1])

    async def check_add_pk_event(self, did: str, tx_hash: str, new_hex_public_key: str):
        self.assertEqual(64, len(tx_hash))
        await asyncio.sleep(randint(10, 15))
        event = await sdk.default_aio_network.get_contract_event_by_tx_hash(tx_hash)
        hex_contract_address = sdk.native_vm.aio_did().contract_address
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertIn('PublicKey', notify['States'])
        self.assertIn('add', notify['States'])
        self.assertIn(did, notify['States'])
        self.assertIn(new_hex_public_key, notify['States'])

    async def check_duplicated_add_pk(self, did: str, ctrl_acct: Account, new_hex_pk: str):
        try:
            await sdk.native_vm.aio_did().add_public_key(did, ctrl_acct, new_hex_pk, acct4, self.gas_price,
                                                            self.gas_limit)
        except SDKException as e:
            self.assertIn('already exists', e.args[1])

    async def check_revoke_pk_event(self, did: str, tx_hash: str, hex_public_key: str):
        self.assertEqual(64, len(tx_hash))
        await asyncio.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        hex_contract_address = sdk.native_vm.aio_did().contract_address
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertIn('PublicKey', notify['States'])
        self.assertIn('remove', notify['States'])
        self.assertIn(did, notify['States'])
        self.assertIn(hex_public_key, notify['States'])

    async def check_duplicated_revoke_pk(self, did: str, ctrl_acct: Account, hex_public_key: str):
        try:
            await sdk.native_vm.aio_did().revoke_public_key(did, ctrl_acct, hex_public_key, acct3,
                                                               self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertIn('public key has already been revoked', e.args[1])

    @not_panic_exception
    @DNA.runner
    async def test_add_and_remove_public_key(self):
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        tx_hash = await sdk.native_vm.aio_did().registry_did(identity.did, ctrl_acct, acct3, self.gas_price,
                                                                   self.gas_limit)
        await self.check_register_did_event(identity.did, tx_hash)

        private_key = utils.get_random_bytes(32)
        public_key = Signature.ec_get_public_key_by_private_key(private_key, Curve.P256)
        hex_new_public_key = public_key.hex()

        tx_hash = await sdk.native_vm.aio_did().add_public_key(identity.did, ctrl_acct, hex_new_public_key, acct4,
                                                                  self.gas_price, self.gas_limit)
        await self.check_add_pk_event(identity.did, tx_hash, hex_new_public_key)
        await self.check_duplicated_add_pk(identity.did, ctrl_acct, hex_new_public_key)

        tx_hash = await sdk.native_vm.aio_did().revoke_public_key(identity.did, ctrl_acct, hex_new_public_key,
                                                                     acct3, self.gas_price, self.gas_limit)
        await self.check_revoke_pk_event(identity.did, tx_hash, hex_new_public_key)
        await self.check_duplicated_revoke_pk(identity.did, ctrl_acct, hex_new_public_key)

    @not_panic_exception
    @DNA.runner
    async def test_add_and_remove_attribute(self):
        did = sdk.native_vm.aio_did()
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        tx_hash = await did.registry_did(identity.did, ctrl_acct, acct3, self.gas_price, self.gas_limit)
        await self.check_register_did_event(identity.did, tx_hash)

        hex_contract_address = did.contract_address
        attribute = Attribute('hello', 'string', 'attribute')
        tx_hash = await did.add_attribute(identity.did, ctrl_acct, attribute, acct2, self.gas_price,
                                             self.gas_limit)
        await asyncio.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual('Attribute', notify['States'][0])
        self.assertEqual('add', notify['States'][1])
        self.assertEqual(identity.did, notify['States'][2])
        self.assertEqual('hello', NeoData.to_utf8_str(notify['States'][3][0]))

        attrib_key = 'hello'
        tx_hash = await did.remove_attribute(identity.did, ctrl_acct, attrib_key, acct3, self.gas_price,
                                                self.gas_limit)
        await asyncio.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual('Attribute', notify['States'][0])
        self.assertEqual('remove', notify['States'][1])
        self.assertEqual(identity.did, notify['States'][2])
        self.assertEqual('hello', NeoData.to_utf8_str(notify['States'][3]))
        try:
            await did.remove_attribute(identity.did, ctrl_acct, attrib_key, acct3, self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertIn('attribute not exist', e.args[1])
        attrib_key = 'key'
        try:
            await did.remove_attribute(identity.did, ctrl_acct, attrib_key, acct3, self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertIn('attribute not exist', e.args[1])

    @not_panic_exception
    @DNA.runner
    async def test_add_recovery(self):
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        tx_hash = await sdk.native_vm.aio_did().registry_did(identity.did, ctrl_acct, acct3, self.gas_price,
                                                                   self.gas_limit)
        await self.check_register_did_event(identity.did, tx_hash)

        rand_private_key = utils.get_random_bytes(32).hex()
        recovery = Account(rand_private_key, SignatureScheme.SHA256withECDSA)
        b58_recovery_address = recovery.get_address_base58()
        tx_hash = await sdk.native_vm.aio_did().add_recovery(identity.did, ctrl_acct, b58_recovery_address, acct2,
                                                                self.gas_price, self.gas_limit)
        await asyncio.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        hex_contract_address = sdk.native_vm.aio_did().contract_address
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('Recovery', notify['States'][0])
        self.assertEqual('add', notify['States'][1])
        self.assertEqual(identity.did, notify['States'][2])
        self.assertEqual(recovery.get_address_hex(little_endian=False), notify['States'][3])
        ddo = await sdk.native_vm.aio_did().get_ddo(identity.did)
        self.assertIn(ctrl_acct.get_did(), ddo['Owners'][0]['PubKeyId'])
        self.assertEqual('ECDSA', ddo['Owners'][0]['Type'])
        self.assertEqual('P256', ddo['Owners'][0]['Curve'])
        self.assertEqual(ctrl_acct.get_public_key_hex(), ddo['Owners'][0]['Value'])
        self.assertEqual(0, len(ddo['Attributes']))
        self.assertEqual(recovery.get_address_base58(), ddo['Recovery'])
        self.assertEqual(identity.did, ddo['DID'])

        rand_private_key = utils.get_random_bytes(32).hex()
        new_recovery = Account(rand_private_key, SignatureScheme.SHA256withECDSA)
        b58_new_recovery_address = new_recovery.get_address_base58()
        try:
            await sdk.native_vm.aio_did().add_recovery(identity.did, ctrl_acct, b58_new_recovery_address, acct2,
                                                          self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertIn('already set recovery', e.args[1])

        private_key = utils.get_random_bytes(32)
        public_key = Signature.ec_get_public_key_by_private_key(private_key, Curve.P256)
        hex_new_public_key = public_key.hex()
        tx_hash = await sdk.native_vm.aio_did().add_public_key(identity.did, recovery, hex_new_public_key, acct2,
                                                                  self.gas_price, self.gas_limit, is_recovery=True)
        await asyncio.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('PublicKey', notify['States'][0])
        self.assertEqual('add', notify['States'][1])
        self.assertEqual(identity.did, notify['States'][2])
        self.assertEqual(2, notify['States'][3])
        self.assertEqual(hex_new_public_key, notify['States'][4])

        ddo = await sdk.native_vm.aio_did().get_ddo(identity.did)
        self.assertIn(ctrl_acct.get_did(), ddo['Owners'][0]['PubKeyId'])
        self.assertEqual('ECDSA', ddo['Owners'][0]['Type'])
        self.assertEqual('P256', ddo['Owners'][0]['Curve'])
        self.assertEqual(ctrl_acct.get_public_key_hex(), ddo['Owners'][0]['Value'])
        self.assertIn(ctrl_acct.get_did(), ddo['Owners'][1]['PubKeyId'])
        self.assertEqual('ECDSA', ddo['Owners'][1]['Type'])
        self.assertEqual('P256', ddo['Owners'][1]['Curve'])
        self.assertEqual(hex_new_public_key, ddo['Owners'][1]['Value'])
        self.assertEqual(0, len(ddo['Attributes']))
        self.assertEqual(recovery.get_address_base58(), ddo['Recovery'])
        self.assertEqual(identity.did, ddo['DID'])
        self.assertEqual(b58_recovery_address, ddo['Recovery'])

        tx_hash = await sdk.native_vm.aio_did().revoke_public_key(identity.did, recovery, hex_new_public_key,
                                                                     acct3, self.gas_price, self.gas_limit, True)
        await self.check_revoke_pk_event(identity.did, tx_hash, hex_new_public_key)
        await self.check_duplicated_revoke_pk(identity.did, ctrl_acct, hex_new_public_key)

        private_key = utils.get_random_bytes(32)
        public_key = Signature.ec_get_public_key_by_private_key(private_key, Curve.P256)
        hex_new_public_key = public_key.hex()
        try:
            await sdk.native_vm.aio_did().add_public_key(identity.did, new_recovery, hex_new_public_key, acct2,
                                                            self.gas_price, self.gas_limit, True)
        except SDKException as e:
            self.assertIn('no authorization', e.args[1])

    @not_panic_exception
    @DNA.runner
    async def test_change_recovery(self):
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        tx_hash = await sdk.native_vm.aio_did().registry_did(identity.did, ctrl_acct, acct3, self.gas_price,
                                                                   self.gas_limit)
        self.assertEqual(64, len(tx_hash))
        await asyncio.sleep(randint(10, 15))
        event = sdk.restful.get_contract_event_by_tx_hash(tx_hash)
        hex_contract_address = sdk.native_vm.aio_did().contract_address
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('Register', notify['States'][0])
        self.assertEqual(identity.did, notify['States'][1])

        rand_private_key = utils.get_random_bytes(32).hex()
        recovery = Account(rand_private_key, SignatureScheme.SHA256withECDSA)
        b58_recovery_address = recovery.get_address_base58()
        tx_hash = await sdk.native_vm.aio_did().add_recovery(identity.did, ctrl_acct, b58_recovery_address, acct2,
                                                                self.gas_price, self.gas_limit)
        await asyncio.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('Recovery', notify['States'][0])
        self.assertEqual('add', notify['States'][1])
        self.assertEqual(identity.did, notify['States'][2])
        self.assertEqual(recovery.get_address_hex(little_endian=False), notify['States'][3])
        ddo = await sdk.native_vm.aio_did().get_ddo(identity.did)
        self.assertIn(ctrl_acct.get_did(), ddo['Owners'][0]['PubKeyId'])
        self.assertEqual('ECDSA', ddo['Owners'][0]['Type'])
        self.assertEqual('P256', ddo['Owners'][0]['Curve'])
        self.assertEqual(ctrl_acct.get_public_key_hex(), ddo['Owners'][0]['Value'])
        self.assertEqual(0, len(ddo['Attributes']))
        self.assertEqual(recovery.get_address_base58(), ddo['Recovery'])
        self.assertEqual(identity.did, ddo['DID'])

        rand_private_key = utils.get_random_bytes(32).hex()
        new_recovery = Account(rand_private_key, SignatureScheme.SHA256withECDSA)
        b58_new_recovery_address = new_recovery.get_address_base58()

        try:
            await sdk.native_vm.aio_did().change_recovery(identity.did, b58_new_recovery_address, ctrl_acct,
                                                             acct2, self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertIn('operator is not the recovery', e.args[1])
        tx_hash = await sdk.native_vm.aio_did().change_recovery(identity.did, b58_new_recovery_address, recovery,
                                                                   acct2, self.gas_price, self.gas_limit)
        await asyncio.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)

        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('Recovery', notify['States'][0])
        self.assertEqual('change', notify['States'][1])
        self.assertEqual(identity.did, notify['States'][2])
        self.assertEqual(new_recovery.get_address_hex(little_endian=False), notify['States'][3])

    @not_panic_exception
    @DNA.runner
    async def test_verify_signature(self):
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        tx_hash = await sdk.native_vm.aio_did().registry_did(identity.did, ctrl_acct, acct3, self.gas_price,
                                                                   self.gas_limit)
        await self.check_register_did_event(identity.did, tx_hash)

        private_key = utils.get_random_bytes(32)
        public_key = Signature.ec_get_public_key_by_private_key(private_key, Curve.P256)
        new_ctrl_acct = Account(private_key)
        hex_new_public_key = public_key.hex()

        tx_hash = await sdk.native_vm.aio_did().add_public_key(identity.did, ctrl_acct, hex_new_public_key, acct4,
                                                                  self.gas_price, self.gas_limit)
        await self.check_add_pk_event(identity.did, tx_hash, hex_new_public_key)

        result = await sdk.native_vm.aio_did().verify_signature(identity.did, 1, ctrl_acct)
        self.assertTrue(result)
        result = await sdk.native_vm.aio_did().verify_signature(identity.did, 2, ctrl_acct)
        self.assertFalse(result)
        result = await sdk.native_vm.aio_did().verify_signature(identity.did, 1, new_ctrl_acct)
        self.assertFalse(result)
        result = await sdk.native_vm.aio_did().verify_signature(identity.did, 2, new_ctrl_acct)
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
