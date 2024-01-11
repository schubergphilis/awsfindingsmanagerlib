#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: backends.py
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
Main code for backends.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import logging
from abc import ABC, abstractmethod

import requests
import yaml

from .validations import validate_rule_data

__author__ = '''Marwin Baumann <mbaumann@schubergphilis.com>, Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''21-11-2023'''
__copyright__ = '''Copyright 2023, Marwin Baumann, Costas Tyfoxylos'''
__credits__ = ["Ben van Breukelen", "Costas Tyfoxylos", "Marwin Baumann"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Ben van Breukelen, Costas Tyfoxylos, Marwin Baumann'''
__email__ = '''<bvanbreukelen@schubergphilis.com>,<ctyfoxylos@schubergphilis.com>,<mbaumann@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''backends'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class Backend(ABC):

    @abstractmethod
    def _get_rules(self):
        """Retrieves the rules from the backend.

        Returns:
            A list of rule data from the backend.

        """

    def get_rules(self):
        return [validate_rule_data(data) for data in self._get_rules()]


class Http(Backend):

    def __init__(self, url):
        self.url = url

    def _get_rules(self):
        response = requests.get(self.url, timeout=2)
        response.raise_for_status()
        data = yaml.safe_load(response.text)
        return data.get('Rules')

#
# class DynamoDB(Backend):
#
#     def _get_rules(self):
#
#
# class S3(Backend):
#
#     def _get_rules(self):
#
#
# class GitHub(Backend)
#
#     def _get_rules(self):
#
#
