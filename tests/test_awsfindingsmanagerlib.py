#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: test_awsfindingsmanagerlib.py
#
# Copyright 2023 Marwin Baumann
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
test_awsfindingsmanagerlib
----------------------------------
Tests for `awsfindingsmanagerlib` module.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

from unittest import TestCase
from unittest.mock import patch, MagicMock
from betamax.fixtures import unittest
from awsfindingsmanagerlib import FindingsManager, Local
import json

__author__ = '''Marwin Baumann <mbaumann@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''21-11-2023'''
__copyright__ = '''Copyright 2023, Marwin Baumann'''
__credits__ = ["Marwin Baumann"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Marwin Baumann'''
__email__ = '''<mbaumann@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class TestAwsfindingsmanagerlib(unittest.BetamaxTestCase):

    def setUp(self):
        """
        Test set up

        This is where you can setup things that you use throughout the tests. This method is called before every test.
        """
        pass

    def tearDown(self):
        """
        Test tear down

        This is where you should tear down what you've setup in setUp before. This method is called after every test.
        """
        pass

class TestBasicRun(TestCase):

    @patch('awsfindingsmanagerlib.FindingsManager._batch_update_findings')
    @patch('awsfindingsmanagerlib.FindingsManager._get_sts_client')
    @patch('awsfindingsmanagerlib.FindingsManager._get_security_hub_client')
    @patch('awsfindingsmanagerlib.FindingsManager._get_ec2_client')
    def test_basic_run(self, mock_ec2: MagicMock, mock_sec_hub_get: MagicMock, mock_sts: MagicMock, mock_update: MagicMock):
        # basic init
        local_backend = Local(path='./tests/fixtures/suppressions.yaml')
        rules = local_backend.get_rules()

        findings_manager = FindingsManager()
        findings_manager.register_rules(rules)

        # configuring mock sec hub to return fixture findings
        mock_sec_hub_client = MagicMock()
        mock_sec_hub_get.return_value = mock_sec_hub_client

        mock_sec_hub_paginator = MagicMock()
        mock_sec_hub_client.get_paginator.return_value = mock_sec_hub_paginator

        with open('./tests/fixtures/findings.json', encoding='utf-8') as findings_file:
            mock_sec_hub_paginator.paginate.return_value = [json.load(findings_file)]

        # basic suppression in action
        self.assertTrue(findings_manager.suppress_matching_findings())

        # load expected api call payload
        with open('tests/fixtures/batch_update_findings.json', encoding='utf-8') as updates_file:
            batch_update_findings = json.load(updates_file)

        # compare expected to actual api call payload
        # sadly this does not work: mock_update.assert_called_once_with(mock_sec_hub_client, batch_update_findings)
        # because FindingIdentifiers is a randomly ordered collection
        mock_update.assert_called_once()

        update_args = mock_update.call_args.args[1]
        self.assertEqual(update_args.keys(), batch_update_findings.keys())

        self.assertEquals(update_args['Note'], batch_update_findings['Note'])
        self.assertEquals(update_args['Workflow'], batch_update_findings['Workflow'])

        self.assertEqual(len(update_args['FindingIdentifiers']), len(batch_update_findings['FindingIdentifiers']))
        for item in update_args['FindingIdentifiers']:
            self.assertIn(item, batch_update_findings['FindingIdentifiers'])
        for item in batch_update_findings['FindingIdentifiers']:
            self.assertIn(item, update_args['FindingIdentifiers'])
