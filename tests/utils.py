#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: utils.py
#
# Copyright 2024 Carlo van Overbeek
#
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

"""
utils
----------------------------------
Test utils for `awsfindingsmanagerlib` module.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

from awsfindingsmanagerlib import Local
from awsfindingsmanagerlib import FindingsManager as FindingsManagerToMock
from unittest.mock import MagicMock
from unittest import TestCase
from typing import List

__author__ = '''Carlo van Overbeek <cvanoverbeek@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''26-06-2024'''
__copyright__ = '''Copyright 2024, Carlo van Overbeek'''
__credits__ = ["Carlo van Overbeek"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Carlo van Overbeek'''
__email__ = '''<cvanoverbeek@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class FindingsManager(FindingsManagerToMock):

    @staticmethod
    def _get_ec2_client(region: str):
        return MagicMock()

    @staticmethod
    def _get_security_hub_client(region: str):
        return MagicMock()

    @staticmethod
    def _get_sts_client():
        return MagicMock()


class FindingsManagerTestCase(TestCase):
    backend_file = './tests/fixtures/suppressions/multiple.yaml'

    def setUp(self) -> None:
        local_backend = Local(self.backend_file)
        rules = local_backend.get_rules()

        self.findings_manager = FindingsManager()
        self.findings_manager.register_rules(rules)

    def assert_batch_update_findings_called_with(self, batch_update_findings_expected: List[dict], _batch_update_findings_mocked: MagicMock):
        """
        Compare expected to actual (=mocked) api call payload.

        Sadly, something like this does not work: _batch_update_findings_mocked.assert_called_once_with(ANY, batch_update_findings),
        because FindingIdentifiers is a randomly ordered collection.
        """
        self.assertEqual(
            len(batch_update_findings_expected),
            _batch_update_findings_mocked.call_count
        )

        for expected in batch_update_findings_expected:
            for call in _batch_update_findings_mocked.call_args_list:
                try:
                    received_args = call.args[1]
                    self.assertEqual(expected.keys(), received_args.keys())
                    self.assertEqual(expected['Note'], received_args['Note'])
                    self.assertEqual(expected['Workflow'], received_args['Workflow'])
                    self.assertEqual(len(expected['FindingIdentifiers']), len(received_args['FindingIdentifiers']))
                    for item in expected['FindingIdentifiers']:
                        self.assertIn(item, received_args['FindingIdentifiers'])
                    break
                except:
                    continue
            else:
                self.assertTrue(False, f'expected call not found: {expected}')
