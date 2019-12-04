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

from dna.claim.claim import Claim
from dna.sigsvr.sigsvr import SigSvr
from dna.claim.proof import BlockchainProof
from dna.merkle.tx_verifier import TxVerifier


class Service(object):
    def __init__(self, sdk):
        self.__sdk = sdk
        self.__sig_svr = None
        self.__claim = None
        self.__tx_verifier = None
        self.__blockchain_proof = None

    def tx_verifier(self):
        if self.__tx_verifier is None:
            self.__tx_verifier = TxVerifier(self.__sdk)
        return self.__tx_verifier

    def blockchain_proof(self):
        if self.__blockchain_proof is None:
            self.__blockchain_proof = BlockchainProof(self.__sdk)
        return self.__blockchain_proof

    def claim(self):
        if self.__claim is None:
            self.__claim = Claim(self.__sdk)
        return self.__claim

    @property
    def sig_svr(self):
        if self.__sig_svr is None:
            self.__sig_svr = SigSvr()
        return self.__sig_svr
