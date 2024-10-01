#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: test_suppressions.py
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
test_suppressions
----------------------------------
Tests for `awsfindingsmanagerlib` module.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

from unittest.mock import patch, MagicMock
from .utils import FindingsManagerTestCase
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


with open('tests/fixtures/findings/api_consolidated.json', encoding='utf-8') as findings_file:
    api_consolidated_findings_fixture = json.load(findings_file)

with open('tests/fixtures/findings/gui_legacy.json', encoding='utf-8') as findings_file:
    gui_legacy_findings_fixture = json.load(findings_file)

with open('tests/fixtures/batch_update_findings.json', encoding='utf-8') as updates_file:
    batch_update_findings_fixture = json.load(updates_file)

with open('tests/fixtures/batch_update_findings_full.json', encoding='utf-8') as updates_file:
    batch_update_findings_full_fixture = json.load(updates_file)

full_findings_fixture = []
for security_control_id in ['S3.8', 'S3.9', 'S3.14', 'S3.20']:
    for env in ['dev', 'acc', 'prd']:
        with open(f'tests/fixtures/findings/full/{security_control_id}/{env}.json', encoding='utf-8') as findings_file:
            full_findings_fixture.append(json.load(findings_file))

# this one goes together with a query based on suppressions/full.yaml
findings_by_security_control_id_fixture = {}
# there is no id S3.8 suppression in suppressions/full.yaml
for security_control_id in ['S3.9', 'S3.14', 'S3.20']:
    findings_by_security_control_id_fixture[security_control_id] = []
    # a query with tags already filters out the non-conforming ones,
    # hence no dev for S3.14
    for env in ['dev', 'acc', 'prd'] if security_control_id != 'S3.14' else ['acc', 'prd']:
        with open(f'tests/fixtures/findings/full/{security_control_id}/{env}.json', encoding='utf-8') as findings_file:
            findings_by_security_control_id_fixture[security_control_id].append(
                json.load(findings_file))

with open('tests/fixtures/matches.json', encoding='utf-8') as matches_file:
    full_matches_fixture = json.load(matches_file)


def batch_update_findings_mock(_, payload):
    return (True, payload)


class TestValidation(FindingsManagerTestCase):
    backend_file = './tests/fixtures/suppressions/single.yaml'

    def test_basic_run(self):
        self.assertEqual(
            [],
            self.findings_manager._construct_findings_on_matching_rules(
                api_consolidated_findings_fixture['Findings'])
        )


class TestLegacyValidation(FindingsManagerTestCase):
    backend_file = './tests/fixtures/suppressions/legacy.yaml'

    def test_basic_run(self):
        self.assertEqual(
            [],
            self.findings_manager._construct_findings_on_matching_rules(
                gui_legacy_findings_fixture)
        )


class TestBasicRun(FindingsManagerTestCase):
    @patch(
        'awsfindingsmanagerlib.FindingsManager._get_security_hub_paginator_iterator',
        lambda *_, **__: [api_consolidated_findings_fixture],
    )
    @patch('awsfindingsmanagerlib.FindingsManager._batch_update_findings', side_effect=batch_update_findings_mock)
    def test_basic_run(self, _batch_update_findings_mocked: MagicMock):
        success, payloads = self.findings_manager.suppress_matching_findings()
        self.assertTrue(success)
        self.assert_batch_update_findings(
            [batch_update_findings_fixture], payloads)


class TestFullSuppressions(FindingsManagerTestCase):
    backend_file = './tests/fixtures/suppressions/full.yaml'

    def test_validation(self):
        self.assertEqual(full_matches_fixture,
                         [dict(finding._data, matched_rule=finding._matched_rule._data)
                          for finding in self.findings_manager._construct_findings_on_matching_rules(full_findings_fixture)]
                         )

    @patch('awsfindingsmanagerlib.FindingsManager._batch_update_findings', side_effect=batch_update_findings_mock)
    def test_payload_construction(self, _batch_update_findings_mocked: MagicMock):
        success, payloads = self.findings_manager.suppress_findings_on_matching_rules(
            full_findings_fixture)
        self.assertTrue(success)
        self.assert_batch_update_findings(
            batch_update_findings_full_fixture, payloads)

    @patch(
        'awsfindingsmanagerlib.FindingsManager._get_security_hub_paginator_iterator',
        lambda *_, **kwargs: [{
            'Findings': findings_by_security_control_id_fixture[kwargs['query_filter']['ComplianceSecurityControlId'][0]['Value']]
        }],
    )
    @patch('awsfindingsmanagerlib.FindingsManager._batch_update_findings', side_effect=batch_update_findings_mock)
    def test_from_query(self, _batch_update_findings_mocked: MagicMock):
        success, payloads = self.findings_manager.suppress_matching_findings()
        self.assertTrue(success)
        self.assert_batch_update_findings(
            batch_update_findings_full_fixture, payloads)
