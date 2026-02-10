#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: test_note_preservation.py
#
# Copyright 2026 Marwin Baumann
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
test_note_preservation
----------------------------------
Tests for `awsfindingsmanagerlib` module.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import json
from unittest import TestCase
from awsfindingsmanagerlib import Finding, Rule

__author__ = '''Marwin Baumann <mbaumann@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''10-02-2026'''
__copyright__ = '''Copyright 2026, Marwin Baumann'''
__credits__ = ["Marwin Baumann"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Marwin Baumann'''
__email__ = '''<mbaumann@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class TestNotePreservation(TestCase):
    """Test note preservation logic when suppressing findings."""

    def setUp(self):
        """Set up test fixtures."""
        self.rule = Rule(
            note="Default - Suppress SSM.7 findings",
            action="SUPPRESSED",
            match_on={"rule_or_control_id": "SSM.7"}
        )

        self.base_finding_data = {
            'FindingProviderFields': {'Types': ['test']},
            'AwsAccountId': '123456789012',
            'RecordState': 'ACTIVE',
            'Resources': [{'Type': 'AwsEc2Instance', 'Id': 'i-1234567890abcdef0'}],
            'UpdatedAt': '2024-01-01T00:00:00.000Z',
            'CompanyName': 'AWS',
            'Description': 'Test finding',
            'Workflow': {'Status': 'NEW'},
            'Title': 'Test Finding',
            'ProductFields': {'ControlId': 'SSM.7'},
            'Id': 'arn:aws:securityhub:eu-west-1:123456789012:security-control/SSM.7/finding/test-1',
            'Severity': {'Label': 'HIGH'},
            'Region': 'eu-west-1',
            'Types': ['Software and Configuration Checks'],
            'ProductName': 'Security Hub',
            'WorkflowState': 'NEW',
            'ProductArn': 'arn:aws:securityhub:eu-west-1::product/aws/securityhub',
            'SchemaVersion': '2018-10-08',
            'GeneratorId': 'security-control/SSM.7',
            'CreatedAt': '2024-01-01T00:00:00.000Z'
        }

    def test_no_existing_note(self):
        """Test scenario 1: No existing note or empty note."""
        finding_data = self.base_finding_data.copy()
        # No Note field at all
        finding = Finding(finding_data)
        finding.matched_rule = self.rule

        # Simulate the payload generation
        from awsfindingsmanagerlib import FindingsManager
        manager = FindingsManager.__new__(FindingsManager)
        manager._suppress_label = "TestManager"

        payloads = list(manager._get_suppressing_payload([finding]))

        self.assertEqual(len(payloads), 1)
        payload = payloads[0]

        note_text = json.loads(payload['Note']['Text'])
        self.assertEqual(note_text, {"suppressionNote": "Default - Suppress SSM.7 findings"})

    def test_empty_existing_note(self):
        """Test scenario 1: Empty string note."""
        finding_data = self.base_finding_data.copy()
        finding_data['Note'] = {'Text': ''}
        finding = Finding(finding_data)
        finding.matched_rule = self.rule

        from awsfindingsmanagerlib import FindingsManager
        manager = FindingsManager.__new__(FindingsManager)
        manager._suppress_label = "TestManager"

        payloads = list(manager._get_suppressing_payload([finding]))

        self.assertEqual(len(payloads), 1)
        payload = payloads[0]

        note_text = json.loads(payload['Note']['Text'])
        self.assertEqual(note_text, {"suppressionNote": "Default - Suppress SSM.7 findings"})

    def test_plain_text_note_replacement(self):
        """Test scenario 2: Existing plain text note should be replaced."""
        finding_data = self.base_finding_data.copy()
        finding_data['Note'] = {'Text': 'testnote'}
        finding = Finding(finding_data)
        finding.matched_rule = self.rule

        from awsfindingsmanagerlib import FindingsManager
        manager = FindingsManager.__new__(FindingsManager)
        manager._suppress_label = "TestManager"

        payloads = list(manager._get_suppressing_payload([finding]))

        self.assertEqual(len(payloads), 1)
        payload = payloads[0]

        note_text = json.loads(payload['Note']['Text'])
        self.assertEqual(note_text, {"suppressionNote": "Default - Suppress SSM.7 findings"})

    def test_json_note_preservation(self):
        """Test scenario 3: Existing JSON note should be merged."""
        finding_data = self.base_finding_data.copy()
        finding_data['Note'] = {'Text': '{"jiraIssue": "PROJ-123"}'}
        finding = Finding(finding_data)
        finding.matched_rule = self.rule

        from awsfindingsmanagerlib import FindingsManager
        manager = FindingsManager.__new__(FindingsManager)
        manager._suppress_label = "TestManager"

        payloads = list(manager._get_suppressing_payload([finding]))

        self.assertEqual(len(payloads), 1)
        payload = payloads[0]

        note_text = json.loads(payload['Note']['Text'])
        self.assertEqual(note_text, {
            "jiraIssue": "PROJ-123",
            "suppressionNote": "Default - Suppress SSM.7 findings"
        })

    def test_json_note_with_multiple_fields(self):
        """Test scenario 3: Existing JSON note with multiple fields should be preserved."""
        finding_data = self.base_finding_data.copy()
        finding_data['Note'] = {'Text': '{"jiraIssue": "PROJ-123", "owner": "team-a", "timestamp": "2024-01-01"}'}
        finding = Finding(finding_data)
        finding.matched_rule = self.rule

        from awsfindingsmanagerlib import FindingsManager
        manager = FindingsManager.__new__(FindingsManager)
        manager._suppress_label = "TestManager"

        payloads = list(manager._get_suppressing_payload([finding]))

        self.assertEqual(len(payloads), 1)
        payload = payloads[0]

        note_text = json.loads(payload['Note']['Text'])
        self.assertEqual(note_text, {
            "jiraIssue": "PROJ-123",
            "owner": "team-a",
            "timestamp": "2024-01-01",
            "suppressionNote": "Default - Suppress SSM.7 findings"
        })

    def test_json_note_overwrites_existing_suppression_note(self):
        """Test that existing suppressionNote is overwritten."""
        finding_data = self.base_finding_data.copy()
        finding_data['Note'] = {'Text': '{"jiraIssue": "PROJ-123", "suppressionNote": "Old note"}'}
        finding = Finding(finding_data)
        finding.matched_rule = self.rule

        from awsfindingsmanagerlib import FindingsManager
        manager = FindingsManager.__new__(FindingsManager)
        manager._suppress_label = "TestManager"

        payloads = list(manager._get_suppressing_payload([finding]))

        self.assertEqual(len(payloads), 1)
        payload = payloads[0]

        note_text = json.loads(payload['Note']['Text'])
        self.assertEqual(note_text, {
            "jiraIssue": "PROJ-123",
            "suppressionNote": "Default - Suppress SSM.7 findings"
        })

    def test_batching_by_note_content(self):
        """Test that findings with identical notes are batched together."""
        # Create multiple findings with same note
        findings = []
        for i in range(3):
            finding_data = self.base_finding_data.copy()
            finding_data['Id'] = f'arn:aws:securityhub:eu-west-1:123456789012:security-control/SSM.7/finding/test-{i}'
            finding_data['Note'] = {'Text': '{"jiraIssue": "PROJ-123"}'}
            finding = Finding(finding_data)
            finding.matched_rule = self.rule
            findings.append(finding)

        from awsfindingsmanagerlib import FindingsManager
        manager = FindingsManager.__new__(FindingsManager)
        manager._suppress_label = "TestManager"

        payloads = list(manager._get_suppressing_payload(findings))

        # All 3 findings should be in a single batch since they have identical notes
        self.assertEqual(len(payloads), 1)
        payload = payloads[0]

        self.assertEqual(len(payload['FindingIdentifiers']), 3)
        note_text = json.loads(payload['Note']['Text'])
        self.assertEqual(note_text, {
            "jiraIssue": "PROJ-123",
            "suppressionNote": "Default - Suppress SSM.7 findings"
        })

    def test_separate_batches_for_different_notes(self):
        """Test that findings with different notes are in separate batches."""
        findings = []

        # Finding 1: No note
        finding_data_1 = self.base_finding_data.copy()
        finding_data_1['Id'] = 'arn:aws:securityhub:eu-west-1:123456789012:security-control/SSM.7/finding/test-1'
        finding_1 = Finding(finding_data_1)
        finding_1.matched_rule = self.rule
        findings.append(finding_1)

        # Finding 2: JSON note with jiraIssue
        finding_data_2 = self.base_finding_data.copy()
        finding_data_2['Id'] = 'arn:aws:securityhub:eu-west-1:123456789012:security-control/SSM.7/finding/test-2'
        finding_data_2['Note'] = {'Text': '{"jiraIssue": "PROJ-123"}'}
        finding_2 = Finding(finding_data_2)
        finding_2.matched_rule = self.rule
        findings.append(finding_2)

        # Finding 3: JSON note with different jiraIssue
        finding_data_3 = self.base_finding_data.copy()
        finding_data_3['Id'] = 'arn:aws:securityhub:eu-west-1:123456789012:security-control/SSM.7/finding/test-3'
        finding_data_3['Note'] = {'Text': '{"jiraIssue": "PROJ-456"}'}
        finding_3 = Finding(finding_data_3)
        finding_3.matched_rule = self.rule
        findings.append(finding_3)

        from awsfindingsmanagerlib import FindingsManager
        manager = FindingsManager.__new__(FindingsManager)
        manager._suppress_label = "TestManager"

        payloads = list(manager._get_suppressing_payload(findings))

        # Should have 3 batches: one for no note, one for PROJ-123, one for PROJ-456
        self.assertEqual(len(payloads), 3)

        # Verify each batch has correct note
        note_texts = [json.loads(p['Note']['Text']) for p in payloads]
        self.assertIn({"suppressionNote": "Default - Suppress SSM.7 findings"}, note_texts)
        self.assertIn({"jiraIssue": "PROJ-123", "suppressionNote": "Default - Suppress SSM.7 findings"}, note_texts)
        self.assertIn({"jiraIssue": "PROJ-456", "suppressionNote": "Default - Suppress SSM.7 findings"}, note_texts)
