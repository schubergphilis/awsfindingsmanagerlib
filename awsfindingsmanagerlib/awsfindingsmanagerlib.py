#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsfindingsmanagerlib.py
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
Main code for awsfindingsmanagerlib.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import logging
from copy import deepcopy
from datetime import datetime

import boto3
import botocore.errorfactory
import botocore.exceptions
from botocore.config import Config
from dateutil.parser import parse
from opnieuw import retry

from .awsfindingsmanagerlibexceptions import (InvalidRegion,
                                              NoRegion,
                                              InvalidOrNoCredentials)
from .configuration import (AWS_FOUNDATIONAL_SECURITY_FRAMEWORK,
                            CIS_AWS_FOUNDATION_FRAMEWORK,
                            PCI_DSS_FRAMEWORK, DEFAULT_SECURITY_HUB_FILTER)
from .validations import validate_allowed_denied_regions, validate_allowed_denied_account_ids

__author__ = '''Marwin Baumann <mbaumann@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''21-11-2023'''
__copyright__ = '''Copyright 2023, Marwin Baumann'''
__credits__ = ["Ben van Breukelen", "Costas Tyfoxylos", "Marwin Baumann"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Ben van Breukelen, Costas Tyfoxylos, Marwin Baumann'''
__email__ = '''<bvanbreukelen@schubergphilis.com>,<ctyfoxylos@schubergphilis.com>,<mbaumann@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''awsfindingsmanagerlib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class Finding:
    """Models a finding."""

    def __init__(self, data: dict) -> None:
        self._data = data
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        """Override the default equals behavior."""
        if not isinstance(other, Finding):
            raise ValueError('Not a Finding object')
        return hash(self) == hash(other)

    def __ne__(self, other):
        """Override the default unequal behavior."""
        if not isinstance(other, Finding):
            raise ValueError('Not a Finding object')
        return hash(self) != hash(other)

    @property
    def aws_account_id(self):
        """Account id."""
        return self._data.get('AwsAccountId')

    @property
    def region(self):
        """Region."""
        return self._data.get('Region')

    @property
    def id(self):  # pylint: disable=invalid-name
        """ID."""
        return self._data.get('Id')

    @property
    def severity(self):
        """Severity."""
        return self._data.get('Severity', {}).get('Label')

    @property
    def title(self):
        """Title."""
        return self._data.get('Title')

    @property
    def description(self):
        """Description."""
        return self._data.get('Description')

    @property
    def remediation_recommendation_text(self):
        """Textual recommendation for remediation."""
        return self._data.get('Remediation', {}).get('Recommendation', {}).get('Text')

    @property
    def remediation_recommendation_url(self):
        """URL for more information on the remediation."""
        return self._data.get('Remediation', {}).get('Recommendation', {}).get('Url')

    @property
    def standards_guide_arn(self):
        """Arn of the compliance standard."""
        return self._data.get('ProductFields', {}).get('StandardsGuideArn')

    @property
    def resources(self):
        """A list of resource dicts."""
        return self._data.get('Resources', [{}])

    @property
    def resource_types(self):
        """Resource type."""
        return [resource.get('Type') for resource in self._data.get('Resources', [{}])]

    @property
    def resource_ids(self):
        """Resource ids."""
        return [resource.get('Id') for resource in self._data.get('Resources', [{}])]

    @property
    def generator_id(self):
        """Generator id."""
        return self._data.get('GeneratorId')

    @property
    def types(self):
        """Types."""
        return self._data.get('Types')

    @property
    def is_cis_aws_foundations_benchmark(self):
        """Is this cis framework finding."""
        return CIS_AWS_FOUNDATION_FRAMEWORK in self.compliance_frameworks

    @property
    def is_pci_dss(self):
        """Is this pci dss framework finding."""
        return PCI_DSS_FRAMEWORK in self.compliance_frameworks

    @property
    def is_aws_foundational_security_best_practices(self):
        """Is this aws foundational security best practices framework finding."""
        return AWS_FOUNDATIONAL_SECURITY_FRAMEWORK in self.compliance_frameworks

    @property
    def workflow_status(self):
        """Workflow status."""
        return self._data.get('Workflow', {}).get('Status')

    @property
    def record_state(self):
        """Record status."""
        return self._data.get('RecordState')

    @property
    def compliance_standards(self):
        """Compliance standards."""
        return [standard.get('StandardsId') for standard in self._data.get('Compliance').get('AssociatedStandards', [])]

    @property
    def compliance_frameworks(self):
        """Compliance frameworks."""
        return [standard.split('/')[1] for standard in self.compliance_standards]

    @property
    def rule_id(self):
        """Rule id."""
        return self._data.get('ProductFields', {}).get('RuleId')

    @property
    def compliance_status(self):
        """Compliance status."""
        return self._data.get('Compliance', {}).get('Status')

    @property
    def compliance_control(self):
        """Compliance control."""
        return self._data.get('Compliance Control')

    @property
    def first_observed_at(self):
        """First observed at."""
        if self._data.get('FirstObservedAt') is None:
            return self._parse_date_time(self._data.get('CreatedAt'))
        return self._parse_date_time(self._data.get('FirstObservedAt'))

    @property
    def last_observed_at(self):
        """Last observed at."""
        if self._data.get('LastObservedAt') is None:
            return self._parse_date_time(self._data.get('UpdatedAt'))
        return self._parse_date_time(self._data.get('LastObservedAt'))

    @property
    def created_at(self):
        """Created at."""
        return self._parse_date_time(self._data.get('CreatedAt'))

    @property
    def updated_at(self):
        """Updated at."""
        return self._parse_date_time(self._data.get('UpdatedAt'))

    def _parse_date_time(self, datetime_string):
        try:
            return parse(datetime_string)
        except ValueError:
            self._logger.warning(f'Could not automatically parse datetime string: "{datetime_string}"')
            return None

    @property
    def days_open(self):
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

    @property
    def original_payload(self):
        """Original payload."""
        return self._data

    @property
    def measurement_data(self):
        """Measurement data for computing the energy label."""
        return {
            'Finding ID': self.id,
            'Account ID': self.aws_account_id,
            'Severity': self.severity,
            'Workflow State': self.workflow_status,
            'Days Open': self.days_open
        }


class FindingsManager:
    """Models security hub and can retrieve findings."""

    def __init__(self, region=None, allowed_regions=None, denied_regions=None):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.allowed_regions, self.denied_regions = validate_allowed_denied_regions(allowed_regions, denied_regions)
        self.sts = self._get_sts_client()
        self.ec2 = self._get_ec2_client(region)
        self._aws_regions = None
        self.aws_region = self._validate_region(region) or self._sts_client_config_region

    def _validate_region(self, region):
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
    def _get_security_hub_client(region):
        try:
            config = Config(region_name=region)
            kwargs = {"config": config}
            client = boto3.client('securityhub', **kwargs)
        except (botocore.exceptions.NoRegionError,
                botocore.exceptions.InvalidRegionError) as msg:
            raise NoRegion(f'Security Hub client requires a valid region set to connect, message was:{msg}') from None
        return client

    @staticmethod
    def _get_ec2_client(region):
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
            raise NoRegion(f'Ec2 client requires a valid region set to connect, message was:{msg}') from None
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
            self._logger.debug(f'Regions in EC2 that were opted in are : {self._aws_regions}')
        if self.allowed_regions:
            self._aws_regions = set(self._aws_regions).intersection(set(self.allowed_regions))
            self._logger.debug(f'Working on allowed regions {self._aws_regions}')
        elif self.denied_regions:
            self._logger.debug(f'Excluding denied regions {self.denied_regions}')
            self._aws_regions = set(self._aws_regions) - set(self.denied_regions)
            self._logger.debug(f'Working on non-denied regions {self._aws_regions}')
        else:
            self._logger.debug('Working on all regions')
        return self._aws_regions

    def _get_aggregating_region(self):
        aggregating_region = None
        try:
            client = self._get_security_hub_client(self.aws_region)
            data = client.list_finding_aggregators()
            aggregating_region = data.get('FindingAggregators')[0].get('FindingAggregatorArn').split(':')[3]
            self._logger.info(f'Found aggregating region {aggregating_region}')
        except (IndexError, botocore.exceptions.ClientError):
            self._logger.debug('Could not get aggregating region, either not set, or a client error')
        return aggregating_region

    @retry(retry_on_exceptions=botocore.exceptions.ClientError)
    def _get_findings(self, query_filter):
        findings = set()
        aggregating_region = self._get_aggregating_region()
        regions_to_retrieve = [aggregating_region] if aggregating_region else self.regions
        for region in regions_to_retrieve:
            self._logger.debug(f'Trying to get findings for region {region}')
            session = boto3.Session(region_name=region)
            security_hub = session.client('securityhub')
            paginator = security_hub.get_paginator('get_findings')
            iterator = paginator.paginate(Filters=query_filter)
            try:
                for page in iterator:
                    for finding_data in page['Findings']:
                        finding = Finding(finding_data)
                        self._logger.debug(f'Adding finding with id {finding.id}')
                        findings.add(finding)
            except (security_hub.exceptions.InvalidAccessException, security_hub.exceptions.AccessDeniedException):
                self._logger.debug(f'No access for Security Hub for region {region}.')
                continue
        return list(findings)

    @staticmethod
    def _calculate_account_id_filter(allowed_account_ids, denied_account_ids):
        """Calculates the filter targeting allowed or denied account ids.

        Args:
            allowed_account_ids: The account ids if any.
            denied_account_ids: The Denied ids if any.

        Returns:
            allowed_account_ids, denied_account_ids (tuple(list,list)): If any is set and are valid.

        """
        allowed_account_ids, denied_account_ids = validate_allowed_denied_account_ids(allowed_account_ids,
                                                                                      denied_account_ids)
        aws_account_ids = []
        if any([allowed_account_ids, denied_account_ids]):
            comparison = 'EQUALS' if allowed_account_ids else 'NOT_EQUALS'
            iterator = allowed_account_ids if allowed_account_ids else denied_account_ids
            aws_account_ids = [{'Comparison': comparison, 'Value': account} for account in iterator]
        return aws_account_ids

    #  pylint: disable=dangerous-default-value
    # NEEDS TO BE MODIFIED
    @staticmethod
    def calculate_query_filter(query_filter=DEFAULT_SECURITY_HUB_FILTER,
                               allowed_account_ids=None,
                               denied_account_ids=None):
        """Calculates a Security Hub compatible filter for retrieving findings.

        Depending on arguments provided for allow list, deny list and frameworks to retrieve a query is constructed to
        retrieve only appropriate findings, offloading the filter on the back end.

        Args:
            query_filter: The default filter if no filter is provided.
            allowed_account_ids: The allow list of account ids to get the findings for.
            denied_account_ids: The deny list of account ids to filter out findings for.

        Returns:
            query_filter (dict): The query filter calculated based on the provided arguments.

        """
        query_filter = deepcopy(query_filter)
        aws_account_ids = FindingsManager._calculate_account_id_filter(allowed_account_ids, denied_account_ids)
        if aws_account_ids:
            query_filter.update({'AwsAccountId': aws_account_ids})
        return query_filter

    def get_findings(self):
        """Retrieves findings from security hub based on a default query.

        Returns:
            findings (list): A list of findings from security hub.

        """
        query_filter = DEFAULT_SECURITY_HUB_FILTER
        return self._get_findings(query_filter)

    def get_findings_by_rule_id(self):
        """Retrieves findings from security hub based on a provided query that filters by rule id.

        Returns:
            findings (list): A list of findings from security hub.

        """
        query_filter = {}  # fix for rule id
        return self._get_findings(query_filter)

    def get_findings_by_control_id(self):
        """Retrieves findings from security hub based on a provided query that filters by control id.

        Returns:
            findings (list): A list of findings from security hub.

        """
        query_filter = {}  # fix for control id
        return self._get_findings(query_filter)

    def get_findings_by_tag(self):
        """Retrieves findings from security hub based on a provided query that filters by tag.

        Returns:
            findings (list): A list of findings from security hub.

        """
        query_filter = {}  # fix for tag
        return self._get_findings(query_filter)

    def suppress_findings(self):
        """Suppresses findings from security hub based on a default query."""

    def suppress_findings_by_rule_id(self):
        """Suppresses findings from security hub based on a query by rule id."""

    def suppress_findings_by_control_id(self):
        """Suppresses findings from security hub based on a query by control id."""

    def suppress_findings_by_tag(self):
        """Suppresses findings from security hub based on a query by tag."""
