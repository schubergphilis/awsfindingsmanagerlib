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


with open('tests/fixtures/findings.json', encoding='utf-8') as findings_file:
    findings_fixture = json.load(findings_file)

with open('tests/fixtures/batch_update_findings.json', encoding='utf-8') as updates_file:
    batch_update_findings_fixture = json.load(updates_file)

class TestValidation(FindingsManagerTestCase):
    backend_file = './tests/fixtures/suppressions/single.yaml'

    def test_basic_run(self):
        self.assertEqual(
            [],
            self.findings_manager._construct_findings_on_matching_rules(findings_fixture['Findings'])
        )

class TestBasicRun(FindingsManagerTestCase):

    @patch('awsfindingsmanagerlib.FindingsManager._get_security_hub_paginator_iterator', lambda *_: [findings_fixture])
    @patch('awsfindingsmanagerlib.FindingsManager._batch_update_findings')
    def test_basic_run(self, _batch_update_findings_mocked: MagicMock):
        self.assertTrue(self.findings_manager.suppress_matching_findings())
        self.assert_batch_update_findings_called_once_with(batch_update_findings_fixture, _batch_update_findings_mocked)
