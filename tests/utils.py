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
import json

__author__ = '''Carlo van Overbeek <cvanoverbeek@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''26-06-2024'''
__copyright__ = '''Copyright 2024, Carlo van Overbeek'''
__credits__ = ["Carlo van Overbeek"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Carlo van Overbeek'''
__email__ = '''<cvanoverbeek@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

with open('tests/fixtures/matching_findings.json', encoding='utf-8') as matching_findings_file:
    findings_fixture = json.load(matching_findings_file)
    with open('tests/fixtures/non_matching_findings.json', encoding='utf-8') as non_matching_findings_file:
        findings_fixture.extend(json.load(non_matching_findings_file))

with open('tests/fixtures/non_matching_findings.json', encoding='utf-8') as non_matching_findings_file:
    non_matching_findings_fixture = json.load(non_matching_findings_file)

with open('tests/fixtures/expected_matched_findings.json', encoding='utf-8') as expected_matched_findings_file:
    expected_matched_findings_fixture = json.load(expected_matched_findings_file)

with open('tests/fixtures/expected_batch_update_findings.json', encoding='utf-8') as batch_update_file:
    expected_batch_update_findings = json.load(batch_update_file)

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
    backend_file = './tests/fixtures/suppressions.yaml'

    def setUp(self) -> None:
        local_backend = Local(self.backend_file)
        rules = local_backend.get_rules()

        self.findings_manager = FindingsManager()
        self.findings_manager.register_rules(rules)

    def assert_batch_update_findings(self, batch_update_findings_expected: List[dict], batch_update_findings: List[dict]):
        """
        Compare expected to actual api call payload.
        """
        self.assertEqual(len(batch_update_findings_expected),
                         len(batch_update_findings))

        for expected in batch_update_findings_expected:
            for finding in batch_update_findings:
                try:
                    self.assertTrue(
                        set(expected.keys()).issubset(set(finding.keys())))
                    self.assertEqual(expected['Note'], finding['Note'])
                    self.assertEqual(
                        expected['Workflow'], finding['Workflow'])
                    self.assertEqual(len(expected['FindingIdentifiers']), len(
                        finding['FindingIdentifiers']))
                    for item in expected['FindingIdentifiers']:
                        self.assertIn(item, finding['FindingIdentifiers'])
                    break
                except:
                    continue
            else:
                self.assertTrue(False, f'expected call not found: {expected}')

def batch_update_findings_mock(_, payload):
    return (True, payload)   

def mock_security_hub_query_response(*_, **kwargs):
    findings_by_identifier_fixture = {}
    for finding in findings_fixture:
        if 'Compliance' in finding and 'SecurityControlId' in finding['Compliance']:
            identifier = finding['Compliance']['SecurityControlId']
        elif 'ControlId' in finding['ProductFields']:
            identifier = finding['ProductFields']['ControlId']
        else:
            identifier = finding['ProductName']
        findings_by_identifier_fixture.setdefault(identifier, [])
        findings_by_identifier_fixture[identifier].append(finding)
    
    if 'ComplianceSecurityControlId' in kwargs['query_filter']:
        return [{'Findings': findings_by_identifier_fixture[kwargs['query_filter']['ComplianceSecurityControlId'][0]['Value']]}]
    elif 'ProductFields' in kwargs['query_filter']:
        return [{'Findings': findings_by_identifier_fixture[kwargs['query_filter']['ProductFields'][0]['Value']]}]
    elif 'ProductName' in kwargs['query_filter']:
        return [{'Findings': findings_by_identifier_fixture[kwargs['query_filter']['ProductName'][0]['Value']]}]
    else:
        return [{'Findings': []}]
