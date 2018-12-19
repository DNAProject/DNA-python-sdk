#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import requests

from typing import List
from urllib.parse import urljoin

from ontology.common.error_code import ErrorCode
from ontology.core.transaction import Transaction
from ontology.exception.exception import SDKException


class RestfulMethod(object):
    @staticmethod
    def get_version(url: str):
        return f'{url}/api/v1/version'

    @staticmethod
    def get_network_id(url: str):
        return f'{url}/api/v1/networkid'

    @staticmethod
    def get_connection_count(url: str):
        return f'{url}/api/v1/node/connectioncount'

    @staticmethod
    def get_gas_price(url: str):
        return f'{url}/api/v1/gasprice'

    @staticmethod
    def get_block_by_height(url: str, height: int):
        return f'{url}/api/v1/block/details/height/{height}?raw=0'

    @staticmethod
    def get_block_height(url: str):
        return f'{url}/api/v1/block/height'

    @staticmethod
    def get_block_by_hash(url: str, block_hash: str):
        return f'{url}/api/v1/block/details/hash/{block_hash}?raw=1'

    @staticmethod
    def get_account_balance(url: str, b58_address: str):
        return f'{url}/api/v1/balance/{b58_address}'

    @staticmethod
    def get_allowance(url: str, asset: str, b58_from_address: str, b58_to_address: str) -> str:
        return f'{url}/api/v1/allowance/{asset}/{b58_from_address}/{b58_to_address}'

    @staticmethod
    def get_transaction(url: str, tx_hash: str):
        return f'{url}/api/v1/transaction/{tx_hash}'

    @staticmethod
    def send_transaction(url: str, ):
        return f'{url}/api/v1/transaction?preExec=0'

    @staticmethod
    def send_transaction_pre_exec(url: str, ):
        return f'{url}/api/v1/transaction?preExec=1'

    @staticmethod
    def get_generate_block_time(url: str):
        return f'{url}/api/v1/node/generateblocktime'

    @staticmethod
    def get_smart_contract(url: str, contract_address: str):
        return f'{url}/api/v1/contract/{contract_address}'

    @staticmethod
    def get_smart_contract_event_by_height(url: str, height: int):
        return f'{url}/api/v1/smartcode/event/transactions/{height}'

    @staticmethod
    def get_smart_contract_event_by_tx_hash(url: str, tx_hash: str):
        return f'{url}/api/v1/smartcode/event/txhash/{tx_hash}'

    @staticmethod
    def get_block_height_by_tx_hash(url: str, tx_hash: str):
        return f'{url}/api/v1/block/height/txhash/{tx_hash}'


GET_STORAGE = '/api/v1/storage/'
GET_MERKLE_PROOF = '/api/v1/merkleproof/'
GET_MEM_POOL_TX_COUNT = '/api/v1/mempool/txcount'
GET_MEM_POOL_TX_STATE = '/api/v1/mempool/txstate/'
GET_GRANT_ONG = '/api/v1/grantong'


class RestfulClient(object):
    def __init__(self, url: str = ''):
        self.__url = url

    def set_address(self, url: str):
        self.__url = url

    def get_address(self):
        return self.__url

    def __post(self, url: str, data: str):
        try:
            response = requests.post(url, data=data, timeout=10)
        except requests.exceptions.MissingSchema as e:
            raise SDKException(ErrorCode.connect_err(e.args[0]))
        except requests.exceptions.ConnectTimeout:
            raise SDKException(ErrorCode.other_error(''.join(['ConnectTimeout: ', self.__url])))
        except requests.exceptions.ConnectionError:
            raise SDKException(ErrorCode.other_error(''.join(['ConnectionError: ', self.__url])))
        if response.status_code != 200:
            raise SDKException(ErrorCode.other_error(response.content.decode('utf-8')))
        try:
            response = json.loads(response.content.decode('utf-8'))
        except json.decoder.JSONDecodeError as e:
            raise SDKException(ErrorCode.other_error(e.args[0]))
        if response['Error'] != 0:
            raise SDKException(ErrorCode.other_error(response['Result']))
        return response

    def __get(self, url: str):
        try:
            response = requests.get(url, timeout=10)
        except requests.exceptions.MissingSchema as e:
            raise SDKException(ErrorCode.connect_err(e.args[0]))
        except requests.exceptions.ConnectTimeout:
            raise SDKException(ErrorCode.other_error(''.join(['ConnectTimeout: ', self.__url])))
        except requests.exceptions.ConnectionError:
            raise SDKException(ErrorCode.other_error(''.join(['ConnectionError: ', self.__url])))
        if response.status_code != 200:
            raise SDKException(ErrorCode.other_error(response.content.decode('utf-8')))
        try:
            response = json.loads(response.content.decode('utf-8'))
        except json.decoder.JSONDecodeError as e:
            raise SDKException(ErrorCode.other_error(e.args[0]))
        if response['Error'] != 0:
            if response['Result'] != '':
                raise SDKException(ErrorCode.other_error(response['Result']))
            else:
                raise SDKException(ErrorCode.other_error(response['Desc']))
        return response

    def get_version(self, is_full: bool = False):
        url = RestfulMethod.get_version(self.__url)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_connection_count(self, is_full: bool = False) -> int:
        url = RestfulMethod.get_connection_count(self.__url)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_gas_price(self, is_full: bool = False) -> int or dict:
        url = RestfulMethod.get_gas_price(self.__url)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']['gasprice']

    def get_network_id(self, is_full: bool = False) -> int or dict:
        url = RestfulMethod.get_network_id(self.__url)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_block_height(self, is_full: bool = False) -> int or dict:
        url = RestfulMethod.get_block_height(self.__url)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_block_height_by_tx_hash(self, tx_hash: str, is_full: bool = False):
        url = RestfulMethod.get_block_height_by_tx_hash(self.__url, tx_hash)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_block_count_by_tx_hash(self, tx_hash: str, is_full: bool = False):
        response = self.get_block_height_by_tx_hash(tx_hash, is_full=True)
        response['Result'] += 1
        if is_full:
            return response
        return response['Result']

    def get_block_count(self, is_full: bool = False) -> int or dict:
        response = self.get_block_height(is_full=True)
        response['Result'] += 1
        if is_full:
            return response
        return response['Result']

    def get_block_by_hash(self, block_hash: str, is_full: bool = False) -> int or dict:
        url = RestfulMethod.get_block_by_hash(self.__url, block_hash)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_block_by_height(self, height: int, is_full: bool = False):
        url = RestfulMethod.get_block_by_height(self.__url, height)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_balance(self, b58_address: str, is_full: bool = False):
        url = RestfulMethod.get_account_balance(self.__url, b58_address)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_allowance(self, asset: str, b58_from_address: str, b58_to_address: str, is_full: bool = False):
        url = RestfulMethod.get_allowance(self.__url, asset, b58_from_address, b58_to_address)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_smart_contract(self, contract_address: str, is_full: bool = False):
        url = RestfulMethod.get_smart_contract(self.__url, contract_address)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_smart_contract_event_by_height(self, height: int, is_full: bool = False) -> List[dict]:
        url = RestfulMethod.get_smart_contract_event_by_height(self.__url, height)
        response = self.__get(url)
        if is_full:
            return response
        result = response['Result']
        if result == '':
            result = list()
        return result

    def get_smart_contract_event_by_count(self, count: int, is_full: bool = False) -> List[dict]:
        return self.get_smart_contract_event_by_height(count - 1, is_full)

    def get_smart_contract_event_by_tx_hash(self, tx_hash: str, is_full: bool = False):
        url = RestfulMethod.get_smart_contract_event_by_tx_hash(self.__url, tx_hash)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def get_transaction_by_tx_hash(self, tx_hash: str, is_full: bool = False):
        url = RestfulMethod.get_transaction(self.__url, tx_hash)
        response = self.__get(url)
        if is_full:
            return response
        return response['Result']

    def send_raw_transaction(self, tx: Transaction, is_full: bool = False):
        hex_tx_data = tx.serialize(is_hex=True).decode('ascii')
        data = f'{{"Action":"sendrawtransaction", "Version":"1.0.0","Data":"{hex_tx_data}"}}'
        url = RestfulMethod.send_transaction(self.__url)
        response = self.__post(url, data)
        if is_full:
            return response
        return response['Result']

    def send_raw_transaction_pre_exec(self, tx: Transaction, is_full: bool = False):
        hex_tx_data = tx.serialize(is_hex=True).decode('ascii')
        data = f'{{"Action":"sendrawtransaction", "Version":"1.0.0","Data":"{hex_tx_data}"}}'
        url = RestfulMethod.send_transaction_pre_exec(self.__url)
        response = self.__post(url, data)
        if is_full:
            return response
        return response['Result']