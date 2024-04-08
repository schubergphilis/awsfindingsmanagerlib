#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: configuration.py
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
Main code for configuration.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import json
import logging
import urllib.error
import urllib.request

from .awsfindingsmanagerlibexceptions import UnableToRetrieveSecurityHubRegions

__author__ = '''Marwin Baumann <mbaumann@schubergphilis.com>, Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''21-11-2023'''
__copyright__ = '''Copyright 2023, Marwin Baumann, Costas Tyfoxylos'''
__credits__ = ["Ben van Breukelen", "Costas Tyfoxylos", "Marwin Baumann"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Ben van Breukelen, Costas Tyfoxylos, Marwin Baumann'''
__email__ = '''<bvanbreukelen@schubergphilis.com>,<ctyfoxylos@schubergphilis.com>,<mbaumann@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''configuration'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

DEFAULT_SECURITY_HUB_FILTER = {'ComplianceStatus': [
    {
        'Value': 'FAILED',
        'Comparison': 'EQUALS'
    },
    {
        'Value': 'WARNING',
        'Comparison': 'EQUALS'
    }
]}


def get_available_security_hub_regions():
    """The regions that security hub can be active in.

    Returns:
        regions (list): A list of strings of the regions that security hub can be active in.

    """
    url = 'https://api.regional-table.region-services.aws.a2z.com/index.json'
    try:
        with urllib.request.urlopen(url) as response:
            response_json = json.loads(response.read())
    except (urllib.error.URLError, ValueError):
        raise UnableToRetrieveSecurityHubRegions('Failed to retrieve applicable AWS regions') from None
    return [entry.get('id', '').split(':')[1]
            for entry in response_json.get('prices')
            if entry.get('id').startswith('securityhub')]


SECURITY_HUB_ACTIVE_REGIONS = ['ap-east-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1',
                               'eu-north-1', 'eu-west-2', 'us-east-2', 'us-gov-west-1', 'us-west-2', 'af-south-1',
                               'ap-northeast-3', 'cn-northwest-1', 'eu-south-1', 'eu-west-1', 'eu-west-3', 'me-south-1',
                               'sa-east-1', 'us-east-1', 'us-west-1', 'ap-northeast-1', 'ap-south-1', 'cn-north-1',
                               'eu-central-1', 'us-gov-east-1']
