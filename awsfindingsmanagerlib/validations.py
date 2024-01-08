#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: validations.py
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
Main code for validations.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import re

from schema import Schema, Optional

from .awsfindingsmanagerlibexceptions import (InvalidAccountListProvided,
                                              MutuallyExclusiveArguments,
                                              InvalidRegionListProvided)
from .configuration import SECURITY_HUB_ACTIVE_REGIONS

__author__ = '''Marwin Baumann <mbaumann@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''21-11-2023'''
__copyright__ = '''Copyright 2023, Marwin Baumann'''
__credits__ = ["Ben van Breukelen", "Costas Tyfoxylos", "Marwin Baumann"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Ben van Breukelen, Costas Tyfoxylos, Marwin Baumann'''
__email__ = '''<bvanbreukelen@schubergphilis.com>,<ctyfoxylos@schubergphilis.com>,<mbaumann@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# match_on = {'match_on': {'control_id': 'EC2.1',
#                          'security_control_id': 'bob',
#                          'resource_ids': ['^arn:aws:apigateway:.*$',
#                                           '^arn:aws:apigateway:.*$'],
#                          'tags': [{'key': 'test', 'value': 'bob'},
#                                   {'key': 'test2', 'value': 'alice'}]}}
#

match_on_schema = Schema({'match_on': {Optional('control_id'): str,
                                       Optional('security_control_id'): str,
                                       Optional('resource_ids'): [str],
                                       Optional('tags'): [{'key': str,
                                                           'value': str}]}
                          })


def is_valid_account_id(account_id):
    """Checks whether a provided account id is a valid AWS account id.

    Args:
        account_id (str): An account id string.

    Returns:
        True if the provided value is a valid AWS account id, false otherwise.

    """
    if not isinstance(account_id, str):
        return False
    return all([len(account_id) == 12, account_id.isdigit()])


def are_valid_account_ids(account_ids):
    """Checks whether a provided list of account ids contains all valid AWS account ids.

    Args:
        account_ids (list): A list of account id strings.

    Returns:
        True if the provided list contains all valid AWS account ids, false otherwise.

    """
    if not isinstance(account_ids, (list, tuple, set)):
        return False
    return all(is_valid_account_id(account) for account in account_ids)


def validate_account_ids(account_ids):
    """Validates a provided string or iterable that it contains valid AWS account ids.

    Args:
        account_ids: A string or iterable of strings with AWS account ids.

    Returns:
        account_ids (list): A list of valid AWS account ids.

    Raises:
        InvalidAccountListProvided: If any of the provided account ids is not a valid AWS account id.

    """
    if account_ids is None:
        return []
    if not isinstance(account_ids, (list, tuple, set, str)):
        raise InvalidAccountListProvided(f'Only list, tuple, set or string of accounts are accepted input, '
                                         f'received: {account_ids}')
    if isinstance(account_ids, str):
        account_ids = [account_ids] if is_valid_account_id(account_ids) else re.split('[^0-9]', account_ids)
    account_ids = sorted(list({account_id for account_id in account_ids if account_id}))
    if not are_valid_account_ids(account_ids):
        raise InvalidAccountListProvided(f'The list provided contains invalid account ids: {account_ids}')
    return account_ids


def validate_allowed_denied_account_ids(allowed_account_ids=None, denied_account_ids=None):
    """Validates provided allow and deny account id lists.

    Not both arguments can contain values as they are logically mutually exclusive. The validations process also
    validates that the arguments contain valid account id values if provided.

    Args:
        allowed_account_ids (str|iterable): A single or multiple account id to validate,
            mutually exclusive with the deny list
        denied_account_ids (str|iterable): A single or multiple account id to validate,
            mutually exclusive with the allow list

    Returns:
        allowed_account_ids, denied_account_ids: A tuple of list values with valid account ids

    Raises:
        MutuallyExclusiveArguments: If both arguments contain values.
        InvalidAccountListProvided: If any of the provided account ids is not a valid AWS account id.

    """
    if all([allowed_account_ids, denied_account_ids]):
        raise MutuallyExclusiveArguments('allow_list and deny_list are mutually exclusive.')
    return validate_account_ids(allowed_account_ids), validate_account_ids(denied_account_ids)


def is_valid_region(region):
    """Checks whether a region provided is a valid Security Hub Region.

    Args:
        region: The region to check

    Returns:
        True if Security Hub is active in that region, False otherwise.

    """
    return region in SECURITY_HUB_ACTIVE_REGIONS


def get_invalid_regions(regions):
    """Calculates if regions are not valid for security hub.

    Args:
        regions: The regions to check

    Returns:
        A set of regions that security hub is not active in

    """
    return set(regions) - set(SECURITY_HUB_ACTIVE_REGIONS)


def validate_regions(regions):
    """Validates provided argument of regions for security hub.

    Args:
        regions: A string or iterable of regions that security hub should be active in.

    Returns:
        A list of valid regions if successful.

    Raises:
        InvalidRegionListProvided: If the regions provided are not valid for security hub.

    """
    if regions is None:
        return regions

    if not isinstance(regions, (list, tuple, set, str)):
        raise InvalidRegionListProvided(f'Only list, tuple, set or string of regions is accepted input, '
                                        f'received: {regions}')
    if isinstance(regions, str):
        regions = [regions] if is_valid_region(regions) else re.split(r'\s', regions)

    invalid_regions = get_invalid_regions(regions)
    if invalid_regions:
        raise InvalidRegionListProvided(f'The following regions provided are not valid for Security Hub. '
                                        f'{invalid_regions}')
    return regions


def validate_allowed_denied_regions(allowed_regions=None, denied_regions=None):
    """Validates provided allow and deny regions.

    Not both arguments can contain values as they are logically mutually exclusive. The validations process also
    validates that the arguments contain valid regions if provided.

    Args:
        allowed_regions (str|iterable): A single or multiple region to validate, mutually exclusive with the deny
        denied_regions (str|iterable): A single or multiple region to validate, mutually exclusive with the allow

    Returns:
        allowed_regions, denied_regions: A tuple of list values with valid regions

    Raises:
        MutuallyExclusiveArguments: If both arguments contain values.
        InvalidRegionListProvided: If any of the provided regions is not a valid Security Hub region.

    """
    if all([allowed_regions, denied_regions]):
        raise MutuallyExclusiveArguments('allowed_regions and denied_regions are mutually exclusive.')
    return validate_regions(allowed_regions), validate_regions(denied_regions)
