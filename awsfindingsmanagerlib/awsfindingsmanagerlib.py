#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsfindingsmanagerlib.py
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
Main code for awsfindingsmanagerlib.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from itertools import islice
from re import search
from typing import List, Dict, Union, Optional

import boto3
import botocore.errorfactory
import botocore.exceptions
from botocore.config import Config
from dateutil.parser import parse
from opnieuw import retry

from .awsfindingsmanagerlibexceptions import (InvalidRegion,
                                              NoRegion,
                                              InvalidOrNoCredentials,
                                              InvalidRuleType,
                                              FailedToBatchUpdate,
                                              NoRuleFindings,
                                              InvalidFindingData)
from .configuration import DEFAULT_SECURITY_HUB_FILTER
from .validations import (validate_allowed_denied_account_ids,
                          validate_allowed_denied_regions,
                          validate_rule_data)

__author__ = '''Marwin Baumann <mbaumann@schubergphilis.com>, Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''21-11-2023'''
__copyright__ = '''Copyright 2023, Marwin Baumann, Costas Tyfoxylos'''
__credits__ = ["Ben van Breukelen", "Costas Tyfoxylos", "Marwin Baumann"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Ben van Breukelen, Costas Tyfoxylos, Marwin Baumann'''
__email__ = '''<bvanbreukelen@schubergphilis.com>,<ctyfoxylos@schubergphilis.com>,<mbaumann@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''awsfindingsmanagerlib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

MAX_SUPPRESSION_PAYLOAD_SIZE = 100


class Finding:
    """Models a finding."""

    required_fields = {'FindingProviderFields', 'AwsAccountId', 'RecordState', 'Resources', 'UpdatedAt', 'CompanyName',
                       'Description', 'Workflow', 'Title', 'ProductFields', 'Id', 'Severity', 'Region', 'Types',
                       'ProductName', 'WorkflowState', 'ProductArn', 'SchemaVersion', 'GeneratorId', 'CreatedAt'}

    def __init__(self, data: Dict) -> None:
        self._data = self._validate_data(data)
        self._logger = logging.getLogger(
            f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self._matched_rule = None

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: Finding) -> bool:
        """Override the default equals behavior."""
        if not isinstance(other, Finding):
            raise ValueError('Not a Finding object')
        return hash(self) == hash(other)

    def __ne__(self, other: Finding) -> bool:
        """Override the default unequal behavior."""
        if not isinstance(other, Finding):
            raise ValueError('Not a Finding object')
        return hash(self) != hash(other)

    @staticmethod
    def _validate_data(data: Dict) -> Dict:
        missing = set(Finding.required_fields) - set(data.keys())
        if missing:
            raise InvalidFindingData(
                f'Missing required keys: "{missing}" for data with ID "{data.get("Id")}"')
        return data

    @property
    def matched_rule(self) -> Rule:
        """The matched rule that is registered in the finding."""
        return self._matched_rule

    @matched_rule.setter
    def matched_rule(self, rule) -> None:
        """The matched rule setter that is registered in the finding."""
        if not isinstance(rule, Rule):
            raise InvalidRuleType(
                f'The argument provided is not a valid rule object. Received: "{rule}"')
        self._matched_rule = rule

    @property
    def aws_account_id(self) -> str:
        """Account id."""
        return self._data.get('AwsAccountId')

    @property
    def product_arn(self) -> str:
        """Product ARN."""
        return self._data.get('ProductArn')

    @property
    def product_name(self) -> str:
        """Product Name."""
        return self._data.get('ProductName')

    @property
    def region(self) -> str:
        """Region."""
        return self._data.get('Region')

    @property
    def id(self) -> str:  # pylint: disable=invalid-name
        """ID."""
        return self._data.get('Id')

    @property
    def severity(self) -> Optional[str]:
        """Severity."""
        return self._data.get('Severity', {}).get('Label')

    @property
    def title(self) -> str:
        """Title."""
        return self._data.get('Title')

    @property
    def description(self) -> str:
        """Description."""
        return self._data.get('Description')

    @property
    def remediation_recommendation_text(self) -> Optional[str]:
        """Textual recommendation for remediation."""
        return self._data.get('Remediation', {}).get('Recommendation', {}).get('Text')

    @property
    def remediation_recommendation_url(self) -> Optional[str]:
        """URL for more information on the remediation."""
        return self._data.get('Remediation', {}).get('Recommendation', {}).get('Url')

    @property
    def standards_guide_arn(self) -> Optional[str]:
        """Arn of the compliance standard."""
        return self._data.get('ProductFields', {}).get('StandardsGuideArn')

    @property
    def rule_id(self) -> Optional[str]:
        """Rule ID."""
        return self._data.get('ProductFields', {}).get('RuleId', '')

    @property
    def control_id(self) -> Optional[str]:
        """Rule ID."""
        return self._data.get('ProductFields', {}).get('ControlId', '')

    @property
    def resources(self) -> Optional[List[Dict]]:
        """A list of resource dicts."""
        return self._data.get('Resources', [{}])

    @property
    def resource_types(self) -> List[Optional[str]]:
        """Resource type."""
        return [resource.get('Type') for resource in self._data.get('Resources', [{}])]

    @property
    def resource_ids(self) -> List[Optional[str]]:
        """Resource ids."""
        return [resource.get('Id') for resource in self._data.get('Resources', [{}])]

    @property
    def tags(self) -> List[Optional[Dict]]:
        """Tags."""
        return [resource.get('Tags') for resource in self._data.get('Resources', []) if resource.get('Tags')]

    @property
    def generator_id(self) -> str:
        """Generator id."""
        return self._data.get('GeneratorId')

    @property
    def types(self) -> Optional[str]:
        """Types."""
        return self._data.get('FindingProviderFields', {}).get('Types')

    @property
    def workflow_status(self) -> str:
        """Workflow status."""
        return self._data.get('Workflow', {}).get('Status')

    @property
    def record_state(self) -> str:
        """Record state."""
        return self._data.get('RecordState')

    @property
    def compliance_standards(self) -> List[str]:
        """Compliance standards."""
        return [standard.get('StandardsId') for standard in self._data.get('Compliance', {}).get('AssociatedStandards',
                                                                                                 [])]

    @property
    def compliance_frameworks(self) -> List[str]:
        """Compliance frameworks."""
        return [standard.split('/')[1] for standard in self.compliance_standards]

    @property
    def compliance_status(self) -> str:
        """Compliance status."""
        return self._data.get('Compliance', {}).get('Status')

    @property
    def security_control_id(self) -> str:
        """Security control ID."""
        return self._data.get('Compliance', {}).get('SecurityControlId', '')

    @property
    def first_observed_at(self) -> Optional[datetime]:
        """First observed at."""
        if self._data.get('FirstObservedAt') is None:
            return self._parse_date_time(self._data.get('CreatedAt'))
        return self._parse_date_time(self._data.get('FirstObservedAt'))

    @property
    def last_observed_at(self) -> Optional[datetime]:
        """Last observed at."""
        if self._data.get('LastObservedAt') is None:
            return self._parse_date_time(self._data.get('UpdatedAt'))
        return self._parse_date_time(self._data.get('LastObservedAt'))

    @property
    def created_at(self) -> Optional[datetime]:
        """Created at."""
        return self._parse_date_time(self._data.get('CreatedAt'))

    @property
    def updated_at(self) -> Optional[datetime]:
        """Updated at."""
        return self._parse_date_time(self._data.get('UpdatedAt'))

    def _parse_date_time(self, datetime_string) -> Optional[datetime]:
        """Parses a datetime string to a datetime object.

        Args:
            datetime_string: The string to parse.

        Returns:
            The converted datetime object.

        """
        try:
            return parse(datetime_string)
        except ValueError:
            self._logger.warning(
                f'Could not automatically parse datetime string: "{datetime_string}"')
            return None

    @property
    def days_open(self) -> int:
        """Days open."""
        if self.workflow_status == 'RESOLVED':
            return 0
        first_observation = self.first_observed_at or self.created_at
        last_observation = self.last_observed_at or datetime.now()
        try:
            return (last_observation - first_observation).days
        except Exception:  # pylint: disable=broad-except
            self._logger.exception('Could not calculate number of days open, '
                                   'last or first observation date is missing.')
            return -1

    def is_matching_resource_ids(self, resource_id_patterns) -> bool:
        """Iterates over all finding resource ids and checks if any match with any of the resource ids provided.

        Args:
            resource_id_patterns: A list of resource ids regular expression patterns.

        Returns:
            True if any match is found, False otherwise.

        """
        return any(search(pattern, resource)
                   for resource in self.resource_ids
                   for pattern in resource_id_patterns)

    def is_matching_tags(self, rule_tags) -> bool:
        """Iterates over all finding tags and checks if any match with any of the rule tags provided.

        Args:
            rule_tags: A list of tags coming from a Rule match_on field.

        Returns:
            True if any match is found, False otherwise.

        """
        return any(tag.get(rule_tag.get('key')) == rule_tag.get('value')
                   for rule_tag in rule_tags
                   for tag in self.tags)

    @staticmethod
    def match_if_set(left, right):
        return all([left == right, all([left, right])])

    def is_matching_rule(self, rule: Rule) -> bool:
        """Checks a rule for a match with the finding.

        If any of control_id, security_control_id, rule_id or product_name and title attributes match between the
        rule and the finding and the rule does not have any filtering attributes like resource_id_regexps or tags
        then it is considered a match. (Big blast radius) only matching on the control or product.

        If the rule has any attributes like resource_id_regexps or tags then a secondary match is searched for any of
        them with the corresponding finding attributes. If any match is found then the rule is found matching if none
        are matching then the rule is not considered a matching rule.

        Args:
            rule: The rule object to match with.

        Returns:
            True if the finding matched the rule, False otherwise.

        Raises:
            InvalidRuleType if the object provided is not a Rule object.

        """
        if not isinstance(rule, Rule):
            raise InvalidRuleType(rule)
        if any([
            self.match_if_set(self.security_control_id,
                              rule.security_control_id),
            self.match_if_set(self.control_id, rule.rule_or_control_id),
            self.match_if_set(self.rule_id, rule.rule_or_control_id),
            all([
                self.match_if_set(self.product_name, rule.product_name),
                self.match_if_set(self.title, rule.title),
            ])
        ]):
            self._logger.debug(
                f'Matched with rule "{rule.note}" on one of "control_id, security_control_id" or \
                    "product_name" and "title"')
            if not any([rule.tags, rule.resource_id_regexps]):
                self._logger.debug(
                    f'Rule "{rule.note}" does not seem to have filters for resources or tags.')
                return True
            if any([self.is_matching_tags(rule.tags), self.is_matching_resource_ids(rule.resource_id_regexps)]):
                self._logger.debug(
                    f'Matched with rule "{rule.note}" either on resources or tags.')
                return True
        return False


class Rule:
    """Models a suppression rule."""

    def __init__(self, note: str, action: str, match_on: Dict) -> None:
        self._data = validate_rule_data(
            {'note': note, 'action': action, 'match_on': match_on})

    def __hash__(self) -> int:
        return hash(self.note)

    def __eq__(self, other: Rule) -> bool:
        """Override the default equals behavior."""
        if not isinstance(other, Rule):
            raise ValueError('Not a Rule object')
        return hash(self) == hash(other)

    def __ne__(self, other: Rule) -> bool:
        """Override the default unequal behavior."""
        if not isinstance(other, Rule):
            raise ValueError('Not a Rule object')
        return hash(self) != hash(other)

    @property
    def data(self) -> Dict:
        return self._data

    @property
    def note(self) -> str:
        return self._data.get('note')

    @property
    def action(self) -> str:
        return self._data.get('action')

    @property
    def match_on(self) -> Dict:
        """The match_on data of the rule."""
        return self._data.get('match_on')

    @property
    def product_name(self) -> str:
        """The product name if any, empty string otherwise."""
        return self.match_on.get('product_name', '')

    @property
    def security_control_id(self) -> str:
        """The security control ID if any, empty string otherwise."""
        return self.match_on.get('security_control_id', '')

    @property
    def rule_or_control_id(self) -> str:
        """The control ID if any, empty string otherwise."""
        return self.match_on.get('rule_or_control_id', '')

    @property
    def resource_id_regexps(self) -> List[Optional[str]]:
        """The resource ids specified under the match_on attribute."""
        return self.match_on.get('resource_id_regexps', [])

    @property
    def title(self) -> str:
        """The title if any, empty string otherwise."""
        return self.match_on.get('title', '')

    @property
    def tags(self) -> List[Optional[str]]:
        """The tags specified under the match_on attribute."""
        return self.match_on.get('tags', [])

    @staticmethod
    def _get_product_name_query(match_on_data) -> Dict:
        """Constructs a valid query based on product name if any.

        Args:
            match_on_data: The match_on data of the Rule

        Returns:
             The query matching the product name, empty dictionary otherwise.

        """
        product_name = match_on_data.get('product_name')
        if not product_name:
            return {}
        return {'ProductName': [{'Value': product_name,
                                 'Comparison': 'EQUALS'}]}

    @staticmethod
    def _get_rule_or_control_id_query(match_on_data) -> Dict:
        """Constructs a valid query based on a set control ID if any.

        Args:
            match_on_data: The match_on data of the Rule

        Returns:
             The query matching the set control ID, empty dictionary otherwise.

        """
        rule_or_control_id = match_on_data.get('rule_or_control_id')
        if not rule_or_control_id:
            return {}
        # For the CIS AWS Foundations Benchmark standard, the field is RuleId
        # for other standards the field is ControlId, so we use both.
        return {'ProductFields': [{'Key': 'ControlId',
                                   'Value': rule_or_control_id,
                                   'Comparison': 'EQUALS'},
                                  {'Key': 'RuleId',
                                   'Value': rule_or_control_id,
                                   'Comparison': 'EQUALS'}]}

    @staticmethod
    def _get_security_control_id_query(match_on_data) -> Dict:
        """Constructs a valid query based on a set security control ID if any.

        Args:
            match_on_data: The match_on data of the Rule

        Returns:
             The query matching the set security control ID, empty dictionary otherwise.

        """
        security_control_id = match_on_data.get('security_control_id')
        if not security_control_id:
            return {}
        return {'ComplianceSecurityControlId': [{'Value': security_control_id,
                                                 'Comparison': 'EQUALS'}]}

    @staticmethod
    def _get_tag_query(match_on_data) -> Dict:
        """Constructs a valid query based on set tags if any.

        Args:
            match_on_data: The match_on data of the Rule

        Returns:
             The query matching the set tags, empty dictionary otherwise.

        """
        tags = match_on_data.get('tags')
        if not tags:
            return {}
        return {'ResourceTags': [{'Key': tag.get('key'),
                                  'Value': tag.get('value'),
                                  'Comparison': 'EQUALS'}
                                 for tag in tags]}

    @staticmethod
    def _get_title_query(match_on_data) -> Dict:
        """Constructs a valid query based on title if any.

        Args:
            match_on_data: The match_on data of the Rule

        Returns:
             The query matching the title, empty dictionary otherwise.

        """
        title = match_on_data.get('title')
        if not title:
            return {}
        return {'Title': [{'Value': title,
                           'Comparison': 'EQUALS'}]}

    @property
    def query_filter(self) -> Dict:
        """The query filter of the Rule based on all set attributes.

        Returns:
            The Security Hub compatible query filter for all attributes set on the Rule.

        """
        query = deepcopy(DEFAULT_SECURITY_HUB_FILTER)
        query.update(self._get_rule_or_control_id_query(self.match_on))
        query.update(self._get_security_control_id_query(self.match_on))
        query.update(self._get_tag_query(self.match_on))
        query.update(self._get_title_query(self.match_on))
        query.update(self._get_product_name_query(self.match_on))
        return deepcopy(query)


class FindingsManager:
    """Models security hub and can retrieve findings and suppress them."""

    # pylint: disable=too-many-arguments, too-many-positional-arguments
    def __init__(self,
                 region: str = None,
                 allowed_regions: Optional[List[str]] = None,
                 denied_regions: Optional[List[str]] = None,
                 allowed_account_ids: Optional[List[str]] = None,
                 denied_account_ids: Optional[List[str]] = None,
                 strict_mode: bool = True,
                 suppress_label: str = None):
        self._logger = logging.getLogger(
            f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.allowed_regions, self.denied_regions = validate_allowed_denied_regions(allowed_regions,
                                                                                    denied_regions)
        self.allowed_account_ids, self.denied_account_ids = validate_allowed_denied_account_ids(allowed_account_ids,
                                                                                                denied_account_ids)
        self.sts = self._get_sts_client()
        self.ec2 = self._get_ec2_client(region)
        self._aws_regions = None
        self.aws_region = self._validate_region(
            region) or self._sts_client_config_region
        self._rules = set()
        self._strict_mode = strict_mode
        self._rules_errors = []
        self._suppress_label = suppress_label or self.__class__.__name__

    @property
    def default_query_filter(self):
        """The default query filter for the instance of FindingManager.

        Calculates the filter based on the provided allowed or denied account ids that should always be provided to
        the remote service.
        """
        return deepcopy(self.update_query_for_account_ids(DEFAULT_SECURITY_HUB_FILTER,
                                                          self.allowed_account_ids,
                                                          self.denied_account_ids))

    @property
    def rules(self) -> List[Rule]:
        """The registered rules of the manager."""
        return list(self._rules)

    @property
    def rules_errors(self):
        """The errors of registered rules if any and strict mode is not set."""
        return self._rules_errors

    def register_rule(self, note: str, action: str, match_on: Dict):
        """Registers a rule by the provided arguments.

        Args:
            note: The note of the rule.
            action: The action of the rule.
            match_on: The "match_on" payload of the rule

        Returns:
            True on success, False otherwise

        Raises:
            InvalidRuleType if strict mode is set and the arguments are not valid for a rule.

        """
        return self.register_rules([{'note': note, 'action': action, 'match_on': match_on}])

    def register_rules(self, rules: List[Dict]):
        """Registers multiple rules by the provided arguments.

        If strict mode is enabled on the service in case of any errors the invalid data is registered under the
        rules_errors attribute.

        Args:
            rules: A list of rule payloads to register.

        Returns:
            True on success, False otherwise

        Raises:
            InvalidRuleType if strict mode is set and the arguments are not valid for a rule.

        """
        if self._strict_mode:
            for data in rules:
                self._rules.add(Rule(**data))
            return True
        success = True
        for data in rules:
            try:
                self._rules.add(Rule(**data))
            except InvalidRuleType:
                success = False
                self._rules_errors.append(data)
                self._logger.exception(f'Rule with data {data} is invalid')
        return success

    def _validate_region(self, region: str):
        if any([not region, region in self.regions]):
            return region
        raise InvalidRegion(region)

    @property
    def _sts_client_config_region(self):
        return self.sts._client_config.region_name  # noqa

    @staticmethod
    def _get_sts_client():
        return boto3.client('sts')

    @staticmethod
    def _get_security_hub_client(region: str):
        try:
            config = Config(region_name=region)
            kwargs = {"config": config}
            client = boto3.client('securityhub', **kwargs)
        except (botocore.exceptions.NoRegionError,
                botocore.exceptions.InvalidRegionError) as msg:
            raise NoRegion(
                f'Security Hub client requires a valid region set to connect, message was: {msg}') from None
        return client

    def _get_security_hub_paginator_iterator(self, region: str, operation_name: str, query_filter: dict):
        security_hub = self._get_security_hub_client(region=region)
        paginator = security_hub.get_paginator(operation_name)
        return paginator.paginate(Filters=query_filter)

    @staticmethod
    def _get_ec2_client(region: str):
        kwargs = {}
        if region:
            config = Config(region_name=region)
            kwargs = {"config": config}
        try:
            client = boto3.client('ec2', **kwargs)
            client.describe_regions()
        except (botocore.exceptions.NoRegionError,
                botocore.exceptions.InvalidRegionError,
                botocore.exceptions.EndpointConnectionError) as msg:
            raise NoRegion(
                f'Ec2 client requires a valid region set to connect, message was: {msg}') from None
        except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as msg:
            raise InvalidOrNoCredentials(msg) from None
        return client

    def _describe_ec2_regions(self):
        return self.ec2.describe_regions().get('Regions')

    @property
    def regions(self):
        """Regions."""
        if self._aws_regions is None:
            self._aws_regions = [region.get('RegionName')
                                 for region in self._describe_ec2_regions()
                                 if region.get('OptInStatus', '') != 'not-opted-in']
            self._logger.debug(
                f'Regions in EC2 that were opted in are: {self._aws_regions}')
        if self.allowed_regions:
            self._aws_regions = set(self._aws_regions).intersection(
                set(self.allowed_regions))
            self._logger.debug(
                f'Working on allowed regions {self._aws_regions}')
        elif self.denied_regions:
            self._logger.debug(
                f'Excluding denied regions {self.denied_regions}')
            self._aws_regions = set(self._aws_regions) - \
                set(self.denied_regions)
            self._logger.debug(
                f'Working on non-denied regions {self._aws_regions}')
        else:
            self._logger.debug('Working on all regions')
        return self._aws_regions

    def _get_aggregating_region(self):
        aggregating_region = None
        try:
            client = self._get_security_hub_client(self.aws_region)
            data = client.list_finding_aggregators()
            aggregating_region = data.get('FindingAggregators')[0].get(
                'FindingAggregatorArn').split(':')[3]
            self._logger.info(f'Found aggregating region {aggregating_region}')
        except (IndexError, botocore.exceptions.ClientError):
            self._logger.debug(
                'Could not get aggregating region, either not set, or a client error')
        return aggregating_region

    @staticmethod
    def _calculate_account_id_filter(allowed_account_ids: Optional[List[str]],
                                     denied_account_ids: Optional[List[str]]):
        """Calculates the filter targeting allowed or denied account ids.

        Args:
            allowed_account_ids: The allowed account ids if any.
            denied_account_ids: The denied account ids if any.

        Returns:
            A list of query filters for the provided allowed or denied account ids.

        """
        allowed_account_ids, denied_account_ids = validate_allowed_denied_account_ids(allowed_account_ids,
                                                                                      denied_account_ids)
        aws_account_ids = []
        if any([allowed_account_ids, denied_account_ids]):
            comparison = 'EQUALS' if allowed_account_ids else 'NOT_EQUALS'
            iterator = allowed_account_ids if allowed_account_ids else denied_account_ids
            aws_account_ids = [{'Comparison': comparison,
                                'Value': account} for account in iterator]
        return aws_account_ids

    #  pylint: disable=dangerous-default-value
    @staticmethod
    def update_query_for_account_ids(query_filter: Dict = DEFAULT_SECURITY_HUB_FILTER,
                                     allowed_account_ids: Optional[List[str]] = None,
                                     denied_account_ids: Optional[List[str]] = None):
        """Calculates a Security Hub compatible filter for retrieving findings.

        Depending on arguments provided for allow list and deny list a query is constructed to
        retrieve only appropriate findings, offloading the filter on the back end.

        Args:
            query_filter: The default filter if no filter is provided.
            allowed_account_ids: The allow list of account ids to get the findings for.
            denied_account_ids: The deny list of account ids to filter out findings for.

        Returns:
            query_filter (dict): The query filter calculated based on the provided arguments.

        """
        query_filter = deepcopy(query_filter)
        aws_account_ids = FindingsManager._calculate_account_id_filter(
            allowed_account_ids, denied_account_ids)
        if aws_account_ids:
            query_filter.update({'AwsAccountId': aws_account_ids})
        return query_filter

    @retry(retry_on_exceptions=botocore.exceptions.ClientError)
    def _get_findings(self, query_filter: Dict):
        findings = set()
        aggregating_region = self._get_aggregating_region()
        regions_to_retrieve = [
            aggregating_region] if aggregating_region else self.regions
        for region in regions_to_retrieve:
            self._logger.debug(f'Trying to get findings for region {region}')
            iterator = self._get_security_hub_paginator_iterator(
                region=region,
                operation_name='get_findings',
                query_filter=query_filter
            )
            try:
                for page in iterator:
                    for finding_data in page['Findings']:
                        finding = Finding(finding_data)
                        self._logger.debug(
                            f'Adding finding with id {finding.id}')
                        findings.add(finding)
            except botocore.exceptions.ClientError as error:
                if error.response['Error']['Code'] in ['AccessDeniedException', 'InvalidAccessException']:
                    self._logger.debug(
                        f'No access for Security Hub for region {region}.')
                    continue
                raise error
        return list(findings)

    @staticmethod
    def _get_matching_findings(rule: Rule, findings: List[Finding], logger: logging.Logger) -> List[Finding]:
        if any([rule.resource_id_regexps, rule.tags]):
            matching_findings = [finding for finding in findings
                                 if any([finding.is_matching_resource_ids(rule.resource_id_regexps),
                                         finding.is_matching_tags(rule.tags)])]
            logger.debug(f'Following findings matched with rule with note: "{rule.note}", '
                         f'{[finding.id for finding in matching_findings]}')
        else:
            logger.debug(
                'No resource id patterns or tags are provided in the rule, all findings used.')
            matching_findings = findings
        for finding in matching_findings:
            finding.matched_rule = rule
        return matching_findings

    def get_findings(self) -> List[Finding]:
        """Retrieves findings from security hub based on the registered rules.

        Returns:
            findings (list): A list of findings from security hub.

        """
        all_findings = []
        for rule in self.rules:
            matching_findings = self.get_findings_by_matching_rule(rule)
            all_findings.extend(matching_findings)
        initial_size = len(all_findings)
        findings = list(set(all_findings))
        diff = initial_size - len(findings)
        if diff:
            self._logger.warning(
                f'Missmatch of finding numbers, there seems to be an overlap of {diff}')
        return findings

    def get_findings_by_matching_rule(self, rule: Rule) -> List[Finding]:
        """Retrieves findings by the provided rule.

        Args:
            rule: The rule to match findings on.

        Returns:
            A list of findings that match the provided rule.

        """
        query = self.default_query_filter
        query.update(rule.query_filter)
        findings = self._get_findings(query)
        return self._get_matching_findings(rule, findings, self._logger)

    def get_findings_by_matching_rule_data(self, note: str, action: str, match_on: Dict) -> List[Finding]:
        """Retrieves findings by the provided rule data.

        Args:
            note: The note of the rule.
            action: The action of the rule
            match_on: The match_on field of the rule.

        Returns:
            A list of findings that match the provided rule data.

        """
        rule = Rule(note, action, match_on)
        return self.get_findings_by_matching_rule(rule)

    @staticmethod
    def _chunk(iterable, size):
        """Chunking an interable to pieces of provided size."""
        iterable = iter(iterable)
        return iter(lambda: tuple(islice(iterable, size)), ())

    def _validate_rule_in_findings(self, findings: List[Finding]):
        """Validates that the provided findinds have registered matching rules.

        Args:
            findings: A list of findings to validate.

        Returns:
            A list of findings with valid matching rules configured.

        Raises:
            NoRuleFindings if strict mode is enabled and any findings do not have matching rules.

        """
        no_rule_matches = [
            finding.id for finding in findings if not finding.matched_rule]
        if no_rule_matches:
            message = f'Findings with the following ids "{no_rule_matches}" do not have matching rules'
            if self._strict_mode:
                raise NoRuleFindings(message)
            self._logger.warning(message)
        return findings

    def _get_suppressing_payload(self, findings: List[Finding]):
        """Constructs a payload compatible with security hub for all findings based on their matching rules.

        Findings are grouped per common rule and a payload of up to MAX_SUPPRESSION_PAYLOAD_SIZE (currently 100 items)
        is constructed per common rule and yielded.

        Args:
            findings: A list of findings to generate suppression payloads for.

        Returns:
            A generator with suppressing payloads per common note chunked at MAX_SUPPRESSION_PAYLOAD_SIZE

        """
        findings = findings if isinstance(
            findings, (list, tuple, set)) else [findings]
        findings = self._validate_rule_in_findings(findings)
        rule_findings_mapping = defaultdict(list)
        for finding in findings:
            rule_findings_mapping[finding.matched_rule].append(finding)
        # payload of FindingIdentifiers cannot be more than 100 items as per 05/01/24
        for rule, findings_ in rule_findings_mapping.items():
            for chunk in FindingsManager._chunk([{'Id': finding.id,
                                                  'ProductArn': finding.product_arn}
                                                 for finding in findings_], MAX_SUPPRESSION_PAYLOAD_SIZE):
                yield {'FindingIdentifiers': chunk,
                       'Workflow': {'Status': rule.action},
                       'Note': {'Text': rule.note,
                                'UpdatedBy': self._suppress_label}}

    def _get_unsuppressing_payload(self, findings: List[Finding]):
        """Constructs a payload compatible with security hub for all findings for unsuppressing.

        Findings are grouped up to MAX_SUPPRESSION_PAYLOAD_SIZE (currently 100 items).

        Args:
            findings: A list of findings to generate unsuppression payloads for.

        Returns:
            A generator with unsuppressing payloads chunked at MAX_SUPPRESSION_PAYLOAD_SIZE

        """
        findings = findings if isinstance(
            findings, (list, tuple, set)) else [findings]
        for chunk in FindingsManager._chunk([{'Id': finding.id,
                                              'ProductArn': finding.product_arn}
                                             for finding in findings], MAX_SUPPRESSION_PAYLOAD_SIZE):
            yield {'FindingIdentifiers': chunk,
                   'Workflow': {'Status': 'NEW'}
                   }

    def suppress_matching_findings(self):
        """Suppresses findings from security hub based the recorded rules."""
        return self._workflow_state_change_on_findings(self.get_findings())

    def suppress_findings(self, findings: List[Finding]):
        """Suppresses findings from security hub based on a provided list."""
        return self._workflow_state_change_on_findings(findings)

    def _workflow_state_change_on_findings(self, findings: List[Finding], suppress=True):
        """Changes workflow state on findings from security hub based on a provided list of findings."""
        message_state = 'suppression' if suppress else 'unsuppression'
        method = self._get_suppressing_payload if suppress else self._get_unsuppressing_payload
        security_hub = self._get_security_hub_client(self.aws_region)
        result = list(self._batch_apply_payloads(security_hub,
                                                method(findings),  # noqa
                                                message_state))
        if result:
            successes, payloads = zip(*result)
        else:
            return (True, [])
        success = all(successes)
        return (success, list(payloads))

    def _batch_apply_payloads(self, security_hub, payloads, message_state):
        for payload in payloads:
            self._logger.debug(
                f'Sending payload {payload} for {message_state} to Security Hub.')
            if os.environ.get('FINDINGS_MANAGER_DRY_RUN_MODE'):
                self._logger.debug(
                    f'Dry run mode is on, skipping the actual {message_state}.')
                continue
            yield self._batch_update_findings(security_hub, payload)

    def _batch_update_findings(self, security_hub, payload):
        """Sends a payload with a batch of max size of 100.

        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub/client/batch_update_findings.html
        The response is of the form :

            {
            'ProcessedFindings': [
                {
                    'Id': 'string',
                    'ProductArn': 'string'
                },
            ],
                'UnprocessedFindings': [
                    {
                        'FindingIdentifier': {
                            'Id': 'string',
                            'ProductArn': 'string'
                        },
                        'ErrorCode': 'string',
                        'ErrorMessage': 'string'
                    },
                ]
            }

        if there are any unprocessed findings it is considered an error.

        Args:
            security_hub: Security hub client
            payload: The payload to send to the service

        Returns:
            tuple: A tuple containing a boolean status and the payload.
            The status is True on success and False otherwise.

        Raises:
            FailedToBatchUpdate: if strict mode is set and there are failures to update.

        """
        status = True
        response = security_hub.batch_update_findings(**payload)
        failed = response.get('UnprocessedFindings')
        if failed:
            if self._strict_mode:
                raise FailedToBatchUpdate(failed)
            status = False
            for fail in failed:
                id_ = fail.get('FindingIdentifier', '').get('Id')
                error = fail.get('ErrorMessage')
                self._logger.error(
                    f'Failed to update finding with ID: "{id_}" with error: "{error}"')
        return (status, payload)

    def validate_finding_on_matching_rules(self, finding_data: Dict):
        """Validates that the provided data is correct data for a finding.

        Iterates all registered rules and tries to match the finding with any registered rule (first match is used).

        Args:
            finding_data: The data of a finding as provided by Security Hub.

        Returns:
            A Finding object with a matching rule on success, None if no rule has been matched.

        Raises:
            InvalidFindingData: The data provided is not valid Finding data.

        """
        finding = Finding(finding_data)
        for rule in self.rules:
            if finding.is_matching_rule(rule):
                finding.matched_rule = rule
                break
        else:
            return None
        return finding

    def _construct_findings_on_matching_rules(self, finding_data: Union[List[Dict], Dict]) -> List[Finding]:
        if isinstance(finding_data, dict):
            finding_data = [finding_data]
        if self._strict_mode:
            findings = [self.validate_finding_on_matching_rules(
                payload) for payload in finding_data]
        else:
            findings = []
            for payload in finding_data:
                try:
                    findings.append(
                        self.validate_finding_on_matching_rules(payload))
                except InvalidFindingData:
                    self._logger.error(f'Data {payload} seems to be invalid.')
        return [finding for finding in findings if finding]

    def suppress_finding_on_matching_rules(self, finding_data: Dict):
        """Suppresses a findings based on the provided finding data.

        A finding gets constructed with the provided data, and all rules are checked for a match with the finding.
        If one is found, the finding is suppressed with the data of the matching rule.

        Args:
            finding_data: The data of a finding as provided by Security Hub.

        Returns:
            tuple: A tuple containing a boolean status and the payload.
            The status is True on success and False otherwise.

        Raises:
            InvalidFindingData: If the data is not valid finding data.

        """
        return self.suppress_findings_on_matching_rules(finding_data)

    def suppress_findings_on_matching_rules(self, finding_data: Union[List[Dict], Dict]):
        """Suppresses a list of findings based on the provided list of finding data.

        All findings get constructed with the provided data, and all rules are checked for a match with each finding.
        If one is found, the finding is suppressed with the data of the matching rule.

        Args:
            finding_data: The data of a finding as provided by Security Hub.

        Returns:
            tuple: A tuple containing a boolean status and the payload.
            The status is True on success and False otherwise.

        Raises:
            InvalidFindingData: If any data is not valid finding data.

        """
        matching_findings = self._construct_findings_on_matching_rules(
            finding_data)
        return self._workflow_state_change_on_findings(matching_findings)

    def get_unmanaged_suppressed_findings(self) -> List[Finding]:
        """Retrieves a list of suppressed findings that are not managed by this library.

        Returns:
            findings (list): A list of findings.

        """
        query = {'NoteUpdatedBy': [{'Value': self._suppress_label,
                                    'Comparison': 'NOT_EQUALS'}],
                 'WorkflowStatus': [{'Value': 'SUPPRESSED',
                                     'Comparison': 'EQUALS'}]}
        return self._get_findings(query)

    def unsuppress_unmanaged_findings(self) -> tuple[bool, list]:
        """Unsuppresses findings that have not been suppressed by this library.

        Returns:
            tuple: A tuple containing a boolean status and the payload.
            The status is True on success and False otherwise.

        """
        return self._workflow_state_change_on_findings(self.get_unmanaged_suppressed_findings(), suppress=False)
