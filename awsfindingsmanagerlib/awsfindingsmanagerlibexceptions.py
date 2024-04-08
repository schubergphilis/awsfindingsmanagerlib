#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsfindingsmanagerlibexceptions.py
#
# Copyright 2023 Marwin Baumann, Costas Tyfoxylos
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
Custom exception code for awsfindingsmanagerlib.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

__author__ = '''Marwin Baumann <mbaumann@schubergphilis.com>, Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''21-11-2023'''
__copyright__ = '''Copyright 2023, Marwin Baumann, Costas Tyfoxylos'''
__credits__ = ["Ben van Breukelen", "Costas Tyfoxylos", "Marwin Baumann"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Ben van Breukelen, Costas Tyfoxylos, Marwin Baumann'''
__email__ = '''<bvanbreukelen@schubergphilis.com>,<ctyfoxylos@schubergphilis.com>,<mbaumann@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class InvalidAccountListProvided(Exception):
    """The list of accounts provided are not valid AWS accounts."""


class InvalidRegionListProvided(Exception):
    """The list of regions provided are not valid AWS regions."""


class MutuallyExclusiveArguments(Exception):
    """The arguments provided are mutually exclusive and only one of the should be provided."""


class InvalidOrNoCredentials(Exception):
    """Invalid or no credentials were provided from the environment."""


class NoRegion(Exception):
    """No region is set on the environment or provided to the library."""


class InvalidRegion(Exception):
    """The region provided is not valid."""


class UnableToRetrieveSecurityHubRegions(Exception):
    """Could not retrieve the regions security hub is active in."""


class InvalidRuleType(Exception):
    """The rule type is not in the accepted rules."""


class InvalidRuleAction(Exception):
    """The rule action is not in the accepted rules."""


class FailedToBatchUpdate(Exception):
    """Failed to batch update security hub findings."""


class MutuallyExclusiveKeys(Exception):
    """Entries on match_on field are provided that are mutually exclusive."""


class NoRuleFindings(Exception):
    """Findings with no rules matched are provided to suppress.

    Depending on the strictness set it might be an error or a warning.
    """


class InvalidFindingData(Exception):
    """The data provided for a finding is invalid."""
