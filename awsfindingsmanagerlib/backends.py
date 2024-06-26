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
from typing import List, Dict

import boto3
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


class Local(Backend):

    def __init__(self, path):
        self.path = path

    def _get_rules(self):
        with open(self.path, encoding='utf-8') as suppressions_file:
            data = yaml.safe_load(suppressions_file)
        return data.get('Rules')


class Http(Backend):

    def __init__(self, url):
        self.url = url

    def _get_rules(self):
        response = requests.get(self.url, timeout=2)
        response.raise_for_status()
        data = yaml.safe_load(response.text)
        return data.get('Rules')


class DynamoDB(Backend):

    def __init__(self, dynamodb_table_name) -> None:
        self._dynamodb_resource = self._get_dynamodb_client()
        self._table = self._get_dynamodb_table(dynamodb_table_name)

    @staticmethod
    def _get_dynamodb_client():
        return boto3.client('dynamodb')

    @staticmethod
    def _get_dynamodb_table(dynamodb_table_name):
        dynamodb_resource = DynamoDB._get_dynamodb_client()
        return dynamodb_resource.Table(name=dynamodb_table_name)

    def _get_rules(self) -> List[Dict]:
        response = self._table.scan()
        data = response['Items']
        while 'LastEvaluatedKey' in response:
            response = self._table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            data.extend(response['Items'])
        # Here iterate over the data and return the payloads.
        # Old code follows.
        # rules = self._suppression_dynamodb_table.get_item(Key={"controlId": self.hash_key})
        # for rule in rules.get('Item', {}).get('data', {}):
        #     self._entries.append(
        #         Rule(action=rule.get('action'),
        #              rules=rule.get('rules'),
        #              notes=rule.get('notes'),
        #              dry_run=rule.get('dry_run', False))
        #     )
        # return self._entries
        return []


class S3(Backend):

    def __init__(self, bucket_name, file_name):
        self._file_contents = self._get_file_contents(bucket_name, file_name)

    @staticmethod
    def _get_file_contents(bucket_name, file_name):
        s3 = boto3.resource('s3')
        return s3.Object(bucket_name, file_name).get()['Body'].read()

    def _get_rules(self):
        data = yaml.safe_load(self._file_contents)
        return data.get('Rules')

# class GitHub(Backend)
#
#     def _get_rules(self):
#
#
