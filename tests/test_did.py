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

import time
import unittest

from Cryptodome.Random.random import randint

from tests import sdk, acct2, acct3, acct4, password, not_panic_exception

from dna.utils import utils
from dna.crypto.curve import Curve
from dna.utils.neo import NeoData
from dna.utils.event import Event
from dna.common.define import DID_ONT
from dna.account.account import Account
from dna.crypto.signature import Signature
from dna.contract.native.did import Attribute
from dna.exception.exception import SDKException
from dna.crypto.signature_scheme import SignatureScheme


class TestDID(unittest.TestCase):
    def setUp(self):
        self.gas_price = 500
        self.gas_limit = 20000

    def check_ecdsa_pk(self, did: str, pk: dict):
        self.assertIn(did, pk['PubKeyId'])
        self.assertEqual('ECDSA', pk['Type'])
        self.assertEqual('P256', pk['Curve'])
        self.assertEqual(66, len(pk['Value']))

    @not_panic_exception
    def check_pk_by_did(self, did):
        pub_keys = sdk.native_vm.did().get_public_keys(did)
        for pk in pub_keys:
            self.check_ecdsa_pk(did, pk)

    @not_panic_exception
    def test_get_public_keys(self):
        did_list = ['did:dna:APywVQ2UKBtitqqJQ9JrpNeY8VFAnrZXiR', 'did:dna:ANDfjwrUroaVtvBguDtrWKRMyxFwvVwnZD']
        for did in did_list:
            self.check_pk_by_did(did)
        try:
            sdk.default_network.connect_to_main_net()
            did = 'did:dna:ATZhaVirdEYkpsHQDn9PMt5kDCq1VPHcTr'
            self.check_pk_by_did(did)
        finally:
            sdk.default_network.connect_to_localhost()

    @not_panic_exception
    def get_ddo_test_case(self, did: str):
        ddo = sdk.native_vm.did().get_ddo(did)
        for pk in ddo['Owners']:
            self.assertIn(did, pk['PubKeyId'])
            self.assertEqual('ECDSA', pk['Type'])
            self.assertEqual('P256', pk['Curve'])
            self.assertEqual(66, len(pk['Value']))
        self.assertEqual(did, ddo['DID'])

    @not_panic_exception
    def test_get_ddo(self):
        did = 'did:dna:AazEvfQPcQ2GEFFPLF1ZLwQ7K5jDn81hve'
        try:
            self.get_ddo_test_case(did)
        finally:
            sdk.default_network.connect_to_localhost()
        try:
            sdk.default_network.connect_to_main_net()
            did = 'did:dna:AP8n55wdQCRePFiNiR4kobGBhvBCMkVPun'
            self.get_ddo_test_case(did)
        finally:
            sdk.default_network.connect_to_localhost()

    @not_panic_exception
    def test_registry_did(self):
        did = sdk.native_vm.did()
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        try:
            did.registry_did(identity.did, ctrl_acct, acct2, self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertEqual(59000, e.args[0])
            self.assertIn('already registered', e.args[1])

    def get_did_contract_notify(self, tx_hash: str):
        self.assertEqual(64, len(tx_hash))
        time.sleep(randint(10, 15))
        event = sdk.default_network.get_contract_event_by_tx_hash(tx_hash)
        return Event.get_notify_by_contract_address(event, sdk.native_vm.did().contract_address)

    def check_register_did_case(self, did: str, tx_hash: str):
        notify = self.get_did_contract_notify(tx_hash)
        self.assertEqual('Register', notify['States'][0])
        self.assertEqual(did, notify['States'][1])

    def check_add_public_key_case(self, did: str, hex_new_pub_key: str, tx_hash: str):
        notify = self.get_did_contract_notify(tx_hash)
        self.assertIn('PublicKey', notify['States'])
        self.assertIn('add', notify['States'])
        self.assertIn(did, notify['States'])
        self.assertIn(hex_new_pub_key, notify['States'])

    def check_remove_public_key_case(self, did: str, hex_removed_pub_key: str, tx_hash: str):
        notify = self.get_did_contract_notify(tx_hash)
        self.assertIn('PublicKey', notify['States'])
        self.assertIn('remove', notify['States'])
        self.assertIn(did, notify['States'])
        self.assertIn(hex_removed_pub_key, notify['States'])

    def check_duplicated_remove_public_key_case(self, did: str, hex_revoker_pub_key: str, ctrl_acct: Account,
                                                payer: Account):
        try:
            sdk.native_vm.did().revoke_public_key(did, ctrl_acct, hex_revoker_pub_key, payer, self.gas_price,
                                                     self.gas_limit)
        except SDKException as e:
            self.assertIn('public key has already been revoked', e.args[1])

    @not_panic_exception
    def test_add_and_remove_public_key(self):
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        did = sdk.native_vm.did()
        tx_hash = did.registry_did(identity.did, ctrl_acct, acct3, self.gas_price, self.gas_limit)
        self.check_register_did_case(identity.did, tx_hash)

        private_key = utils.get_random_bytes(32)
        public_key = Signature.ec_get_public_key_by_private_key(private_key, Curve.P256)
        hex_new_public_key = public_key.hex()

        tx_hash = sdk.native_vm.did().add_public_key(identity.did, ctrl_acct, hex_new_public_key, acct4,
                                                        self.gas_price, self.gas_limit)
        self.check_add_public_key_case(identity.did, hex_new_public_key, tx_hash)
        try:
            did.add_public_key(identity.did, ctrl_acct, hex_new_public_key, acct4, self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertIn('already exists', e.args[1])
        tx_hash = sdk.native_vm.did().revoke_public_key(identity.did, ctrl_acct, hex_new_public_key, acct3,
                                                           self.gas_price, self.gas_limit)
        self.check_remove_public_key_case(identity.did, hex_new_public_key, tx_hash)
        self.check_duplicated_remove_public_key_case(identity.did, hex_new_public_key, ctrl_acct, acct3)

    @not_panic_exception
    def test_add_and_remove_attribute(self):
        did = sdk.native_vm.did()
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        tx_hash = did.registry_did(identity.did, ctrl_acct, acct3, self.gas_price, self.gas_limit)
        self.assertEqual(64, len(tx_hash))
        time.sleep(randint(10, 15))
        event = sdk.restful.get_contract_event_by_tx_hash(tx_hash)
        hex_contract_address = sdk.native_vm.did().contract_address
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('Register', notify['States'][0])
        self.assertEqual(identity.did, notify['States'][1])

        attribute = Attribute('hello', 'string', 'attribute')
        tx_hash = did.add_attribute(identity.did, ctrl_acct, attribute, acct2, self.gas_price, self.gas_limit)
        time.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual('Attribute', notify['States'][0])
        self.assertEqual('add', notify['States'][1])
        self.assertEqual(identity.did, notify['States'][2])
        self.assertEqual('hello', NeoData.to_utf8_str(notify['States'][3][0]))

        attrib_key = 'hello'
        tx_hash = did.remove_attribute(identity.did, ctrl_acct, attrib_key, acct3, self.gas_price, self.gas_limit)
        time.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual('Attribute', notify['States'][0])
        self.assertEqual('remove', notify['States'][1])
        self.assertEqual(identity.did, notify['States'][2])
        self.assertEqual('hello', NeoData.to_utf8_str(notify['States'][3]))
        try:
            did.remove_attribute(identity.did, ctrl_acct, attrib_key, acct3, self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertIn('attribute not exist', e.args[1])
        attrib_key = 'key'
        try:
            did.remove_attribute(identity.did, ctrl_acct, attrib_key, acct3, self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertIn('attribute not exist', e.args[1])

    @not_panic_exception
    def test_new_remove_attribute_transaction(self):
        did = sdk.native_vm.did()
        hex_public_key = acct2.get_public_key_hex()
        b58_address = acct2.get_address_base58()
        acct_did = "did:dna:" + b58_address
        path = 'try'
        tx = did.new_remove_attribute_tx(acct_did, hex_public_key, path, b58_address, self.gas_price, self.gas_limit)
        tx.sign_transaction(acct2)
        try:
            tx_hash = sdk.rpc.send_raw_transaction(tx)
            self.assertEqual(tx.hash256_explorer(), tx_hash)
            time.sleep(randint(10, 15))
            notify = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)['Notify']
            self.assertEqual('Attribute', notify[0]['States'][0])
            self.assertEqual('remove', notify[0]['States'][1])
            self.assertEqual(acct_did, notify[0]['States'][2])
            self.assertEqual('try', bytes.fromhex(notify[0]['States'][3]).decode())
        except SDKException as e:
            self.assertEqual(59000, e.args[0])
            self.assertIn('attribute not exist', e.args[1])

    def check_add_recovery_case(self, did: str, hex_recovery_address: str, tx_hash: str):
        notify = self.get_did_contract_notify(tx_hash)
        self.assertEqual(sdk.native_vm.did().contract_address, notify['ContractAddress'])
        self.assertEqual('Recovery', notify['States'][0])
        self.assertEqual('add', notify['States'][1])
        self.assertEqual(did, notify['States'][2])
        self.assertEqual(hex_recovery_address, notify['States'][3])

    @not_panic_exception
    def test_add_recovery(self):
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        tx_hash = sdk.native_vm.did().registry_did(identity.did, ctrl_acct, acct3, self.gas_price,
                                                         self.gas_limit)
        self.check_register_did_case(identity.did, tx_hash)

        rand_private_key = utils.get_random_bytes(32).hex()
        recovery = Account(rand_private_key, SignatureScheme.SHA256withECDSA)
        b58_recovery_address = recovery.get_address_base58()
        tx_hash = sdk.native_vm.did().add_recovery(identity.did, ctrl_acct, b58_recovery_address, acct2,
                                                      self.gas_price, self.gas_limit)
        self.check_add_recovery_case(identity.did, recovery.get_address().hex(little_endian=False), tx_hash)

        ddo = sdk.native_vm.did().get_ddo(identity.did)
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
            sdk.native_vm.did().add_recovery(identity.did, ctrl_acct, b58_new_recovery_address, acct2,
                                                self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertIn('already set recovery', e.args[1])

        private_key = utils.get_random_bytes(32)
        public_key = Signature.ec_get_public_key_by_private_key(private_key, Curve.P256)
        hex_new_public_key = public_key.hex()
        tx_hash = sdk.native_vm.did().add_public_key(identity.did, recovery, hex_new_public_key, acct2,
                                                        self.gas_price, self.gas_limit, True)
        self.check_add_public_key_case(identity.did, hex_new_public_key, tx_hash)

        ddo = sdk.native_vm.did().get_ddo(identity.did)
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

        tx_hash = sdk.native_vm.did().revoke_public_key(identity.did, recovery, hex_new_public_key, acct3,
                                                           self.gas_price, self.gas_limit, True)
        self.check_remove_public_key_case(identity.did, hex_new_public_key, tx_hash)
        self.check_duplicated_remove_public_key_case(identity.did, hex_new_public_key, ctrl_acct, acct3)

        private_key = utils.get_random_bytes(32)
        public_key = Signature.ec_get_public_key_by_private_key(private_key, Curve.P256)
        hex_new_public_key = public_key.hex()
        try:
            sdk.native_vm.did().add_public_key(identity.did, new_recovery, hex_new_public_key, acct2,
                                                  self.gas_price, self.gas_limit, True)
        except SDKException as e:
            self.assertIn('no authorization', e.args[1])

    @not_panic_exception
    def test_change_recovery(self):
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        tx_hash = sdk.native_vm.did().registry_did(identity.did, ctrl_acct, acct3, self.gas_price,
                                                         self.gas_limit)
        self.assertEqual(64, len(tx_hash))
        time.sleep(randint(10, 15))
        event = sdk.restful.get_contract_event_by_tx_hash(tx_hash)
        hex_contract_address = sdk.native_vm.did().contract_address
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('Register', notify['States'][0])
        self.assertEqual(identity.did, notify['States'][1])

        rand_private_key = utils.get_random_bytes(32).hex()
        recovery = Account(rand_private_key, SignatureScheme.SHA256withECDSA)
        b58_recovery_address = recovery.get_address_base58()
        tx_hash = sdk.native_vm.did().add_recovery(identity.did, ctrl_acct, b58_recovery_address, acct2,
                                                      self.gas_price, self.gas_limit)
        time.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('Recovery', notify['States'][0])
        self.assertEqual('add', notify['States'][1])
        self.assertEqual(identity.did, notify['States'][2])
        self.assertEqual(recovery.get_address_hex(little_endian=False), notify['States'][3])
        ddo = sdk.native_vm.did().get_ddo(identity.did)
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
            sdk.native_vm.did().change_recovery(identity.did, b58_new_recovery_address, ctrl_acct, acct2,
                                                   self.gas_price, self.gas_limit)
        except SDKException as e:
            self.assertIn('operator is not the recovery', e.args[1])
        tx_hash = sdk.native_vm.did().change_recovery(identity.did, b58_new_recovery_address, recovery, acct2,
                                                         self.gas_price, self.gas_limit)
        time.sleep(randint(10, 15))
        event = sdk.rpc.get_contract_event_by_tx_hash(tx_hash)
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)

        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('Recovery', notify['States'][0])
        self.assertEqual('change', notify['States'][1])
        self.assertEqual(identity.did, notify['States'][2])
        self.assertEqual(new_recovery.get_address_hex(little_endian=False), notify['States'][3])

    @not_panic_exception
    def test_verify_signature(self):
        identity = sdk.wallet_manager.create_identity(password)
        ctrl_acct = sdk.wallet_manager.get_control_account_by_index(identity.did, 0, password)
        did = sdk.native_vm.did()
        tx_hash = did.registry_did(identity.did, ctrl_acct, acct3, self.gas_price, self.gas_limit)
        self.assertEqual(64, len(tx_hash))
        time.sleep(randint(10, 15))
        event = sdk.default_network.get_contract_event_by_tx_hash(tx_hash)
        hex_contract_address = did.contract_address
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertEqual(hex_contract_address, notify['ContractAddress'])
        self.assertEqual('Register', notify['States'][0])
        self.assertEqual(identity.did, notify['States'][1])

        private_key = utils.get_random_bytes(32)
        public_key = Signature.ec_get_public_key_by_private_key(private_key, Curve.P256)
        new_ctrl_acct = Account(private_key)
        hex_new_public_key = public_key.hex()

        tx_hash = did.add_public_key(identity.did, ctrl_acct, hex_new_public_key, acct4, self.gas_price,
                                        self.gas_limit)
        time.sleep(randint(10, 15))
        event = sdk.default_network.get_contract_event_by_tx_hash(tx_hash)
        notify = Event.get_notify_by_contract_address(event, hex_contract_address)
        self.assertIn('PublicKey', notify['States'])
        self.assertIn('add', notify['States'])
        self.assertIn(identity.did, notify['States'])
        self.assertIn(hex_new_public_key, notify['States'])
        result = did.verify_signature(identity.did, 1, ctrl_acct)
        self.assertTrue(result)
        result = did.verify_signature(identity.did, 2, ctrl_acct)
        self.assertFalse(result)
        result = did.verify_signature(identity.did, 1, new_ctrl_acct)
        self.assertFalse(result)
        result = did.verify_signature(identity.did, 2, new_ctrl_acct)
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
