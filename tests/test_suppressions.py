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
from .utils import (
    FindingsManagerTestCase,
    mock_security_hub_query_response,
    batch_update_findings_mock,
    findings_fixture,
    non_matching_findings_fixture,
    expected_matched_findings_fixture,
    expected_batch_update_findings,
)

__author__ = '''Carlo van Overbeek <cvanoverbeek@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''26-06-2024'''
__copyright__ = '''Copyright 2024, Carlo van Overbeek'''
__credits__ = ["Carlo van Overbeek"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Carlo van Overbeek'''
__email__ = '''<cvanoverbeek@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

class TestNoSuppressions(FindingsManagerTestCase):
    backend_file = './tests/fixtures/rules_empty.yaml'

    @patch(
        'awsfindingsmanagerlib.FindingsManager._get_security_hub_paginator_iterator',
        lambda *_, **__: [{'Findings': findings_fixture}],
    )
    @patch('awsfindingsmanagerlib.FindingsManager._batch_update_findings', side_effect=batch_update_findings_mock)
    def test_can_run_empty_rules(self, _batch_update_findings_mocked: MagicMock):
        "Test if having findings but no suppression rules returns an empty list."
        success, payloads = self.findings_manager.suppress_matching_findings()
        self.assertTrue(success)
        self.assertListEqual([], payloads)

class TestSuppressions(FindingsManagerTestCase):
    def test_can_ignore_non_suppressed_findings(self):
        """Test if having no matches between findings and suppression rules returns an empty list."""
        self.assertEqual(
            [],
            self.findings_manager._construct_findings_on_matching_rules(non_matching_findings_fixture)
        )

    def test_can_match_suppressions_with_findings(self):
        """Test if having  matching and non-matching findings returns only the ones that match the suppression rules."""
        matched_findings = [dict(finding._data, matched_rule=finding._matched_rule._data)
                          for finding in self.findings_manager._construct_findings_on_matching_rules(findings_fixture)]
        self.assertEqual(len(expected_matched_findings_fixture), len(matched_findings))
        for finding in matched_findings:
            self.assertIn(finding, expected_matched_findings_fixture)

    @patch('awsfindingsmanagerlib.FindingsManager._batch_update_findings', side_effect=batch_update_findings_mock)
    def test_can_suppress_using_events(self, _batch_update_findings_mocked: MagicMock):
        """Test if can suppress based on findings events"""
        success, suppression_updates = self.findings_manager.suppress_findings_on_matching_rules(
            findings_fixture)
        self.assertTrue(success)
        self.assert_batch_update_findings(
            expected_batch_update_findings, suppression_updates)

    @patch(
        'awsfindingsmanagerlib.FindingsManager._get_security_hub_paginator_iterator',
        mock_security_hub_query_response,
    )
    @patch('awsfindingsmanagerlib.FindingsManager._batch_update_findings', side_effect=batch_update_findings_mock)
    def test_can_suppress_using_query(self, _batch_update_findings_mocked: MagicMock):
        """Test if can suppress based on SecurityHub query results"""
        success, suppression_updates = self.findings_manager.suppress_matching_findings()
        self.assertTrue(success)
        self.assert_batch_update_findings(
            expected_batch_update_findings, suppression_updates)
