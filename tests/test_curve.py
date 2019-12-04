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

import unittest

from dna.crypto.curve import Curve
from dna.exception.exception import SDKException


class CurveTest(unittest.TestCase):
    def test_from_label(self):
        self.assertRaises(SDKException, Curve.from_label, 0)
        curve_lst = ['P224', 'P256', 'P384', 'P521']
        label_lst = [1, 2, 3, 4]
        for index, label in enumerate(label_lst):
            self.assertEqual(curve_lst[index], Curve.from_label(label))


if __name__ == '__main__':
    unittest.main()
