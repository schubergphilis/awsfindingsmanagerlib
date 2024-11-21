.. awsfindingsmanagerlib documentation master file, created by
   sphinx-quickstart on 2023-11-21.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

===================
awsfindingsmanagerlib
===================


Quickstart
==========

Installation
------------

Install with your favorite Python package manager like::

  pip install awsfindingsmanagerlib


Define Your Rules
-----------------

You can define rules in multiple ways, the most common are:

1. **Using a YAML File**

Create a YAML file, such as ``rules.yaml``, defining the findings you want to suppress. For example:

.. code-block:: yaml

  Rules:
    - note: Suppress DynamoDB Autoscaling findings
      action: SUPPRESSED
      match_on:
        security_control_id: DynamoDB.1
    - note: Suppress findings for development resources
      action: SUPPRESSED
      match_on:
        tags:
          - key: env
            value: dev


Host the file on an HTTP server (e.g., using ``python3 -m http.server``) or use it directly in your project.

.. code-block:: python

  from awsfindingsmanagerlib import FindingsManager, Http

  http_backend = Http('http://localhost:8000/rules.yaml')

  findings_manager = FindingsManager('eu-west-1')
  findings_manager.register_rules(http_backend.get_rules())
  findings_manager.suppress_matching_findings()

And zip 🤐 all noise is silenced.

2. **Programmatically with `register_rule`**

If you prefer a more dynamic approach, you can define rules programmatically using the ``register_rule`` method:

.. code-block:: python

  from awsfindingsmanagerlib import FindingsManager

  findings_manager = FindingsManager('eu-west-1')
  findings_manager.register_rule(
    note="Suppress DynamoDB Autoscaling findings",
    action="SUPPRESSED",
    match_on={"security_control_id": "DynamoDB.1"}
  )
  findings_manager.suppress_matching_findings()

And zip 🤐 all noise is silenced.


Rule Syntax
===========

Rules in your YAML file follow this general syntax:

.. code-block:: yaml

  Rules:
    - note: 'str' # A descriptive note for the rule
      action: 'SUPPRESSED'
      match_on:
        security_control_id: 'str'
        rule_or_control_id: 'str'
        product_name: 'str'
        title: 'str' 
        tags:
          - key: 'str'
            value: 'str'
        resource_id_regexps:
          - 'regex'

**When Suppressing Native Security Hub Findings**:

Specify either ``security_control_id`` or ``rule_or_control_id`` — but not both!.

*If ``rule_or_control_id`` is used, ensure that "consolidated control findings" is disabled in AWS Security Hub.*

**When Suppressing Findings from AWS Security Hub Service Integrations**:

Specify both ``product_name`` and ``title``. 
The ``product_name`` field must match the name of the product that created the finding (e.g., Inspector). 
The ``title`` field must match the title of the finding.
Read the `AWS service integrations <https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-internal-providers.html#internal-integrations-summary>`_ page for all the supported integrations.

**Additional Filters**:

Either ``tags`` or ``resource_id_regexps`` (or both) can be provided to ensure precise matching.


Valid Credentials
==============================

To ensure successful operation, your AWS credentials must include the following permissions:

- ``ec2:DescribeRegions``
- ``securityhub:GetFindings``
- ``securityhub:BatchUpdateFindings``


Why use awsfindingsmanagerlib?
==============================

You may wonder what justifies using a dedicated lib to suppress findings.
You could have just as easily, maybe even more easily clicked suppress in the console, right?
Yes, BUT, actually, multiple buts.
Let's sum up the advantages of using awsfindingsmanagerlib from the skeptic's perspective.

"I can just do this in the AWS console"
---------------------------------------

Well, that will be a tedious amount of clicking for a lot false positives, while you could have just written:

.. code-block:: yaml

  Rules:
    - note: My dev instance
      action: SUPPRESSED
      match_on:
        resource_ids:
          - arn:aws:ec2:eu-central-1:1234567890:instance/i-1234567890

Maybe, better yet:

.. code-block:: yaml

  Rules:
    - note: dev resources by tag
      action: SUPPRESSED
      match_on:
        tags:
          - key: env
            value: dev
    - note: dev resources by name
      action: SUPPRESSED
      match_on:
        resource_ids:
          - '*-dev$' # yes, we support regex

Add this point you might almost get scared of being too suppressive.
Don't panic:

.. code-block:: yaml

  Rules:
    - note: We'll make this one exception, especially for you two then
      action: SUPPRESSED
      match_on:
        security_control_id: 'IAM.3'
        resource_ids:
          - '^arn:aws:iam::1234567890:user/lazyperson1$'
          - '^arn:aws:iam::1234567890:user/lazyperson2$'

As you can see, suppressions can now be expressed in a more general, meaningful, dare-we-say-Pythonic way.
Moreover, you can apply your suppressions over all your AWS accounts with this tool with little effort.
Control ids are the same in every AWS account and you can express you resources with tags and regex.
This way, your suppressions become portable through your whole environment.

The generality makes it possible to apply the suppressions even in your audit account, despite differing AWS account ids.
This way you can get a truly good overview without clutter from false positives.

"I don't have that many findings to suppress"
---------------------------------------------

Even if you don't have many false positives in your environment, findings are only saved for 90 days.
After that time your suppressions are gone with them.
Most checks immediately generate a new finding then.
Re-suppressing these findings each time manually is error-prone and can eventually amount to a lot of work.

To reduce errors further, we recommend storing your suppressions file in a VCS and suppressing in full automation.
(See below for our :ref:`reference implementation <reference-implementation>`.)


Third-Party Tools
-----------------

While tools like Splunk, Datadog, and OpenSearch excel at aggregation and analysis, managing findings **at the source** in AWS Security Hub offers significant advantages. Suppressing irrelevant findings within AWS Security Hub ensures:

- Only relevant data is forwarded to third-party tools, reducing noise and enhancing visibility.
- Lower costs due to reduced storage requirements and improved query performance.


AWS Security Hub Automations
----------------------------

AWS Security Hub Automations is AWS's native solution for managing findings. However, it has several limitations that can hinder its effectiveness in large or complex environments:

Rule Count
----------
Automations are limited to **100 rules**, which can quickly become insufficient in large environments. Each unique suppression scenario often requires its own rule, leading to a rapid depletion of the rule quota.

Flexibility
-----------
Automations lack support for **regex** or **multi-property rules**, making them less flexible for complex suppression needs. For example, suppressing a specific check across multiple resources in Automations requires creating multiple rules. 

With regex, you can achieve the same result with a single, concise rule. For instance, to suppress findings for Lambda functions in specific dev/test accounts, you could use:

`arn:aws:lambda:eu-central-1:(1234567890|2345678901):function:(client-a|client-b|client-c)`

In Automations, this scenario would require separate rules for each permutation, increasing rule count and reducing manageability.

Retroactive Suppression
-----------------------
Unlike Automations, this library supports **retroactive suppression**, allowing you to address findings from the past. This eliminates the need to wait for the 90-day retention period to expire before irrelevant findings stop cluttering your dashboard.

Readability
-----------
While regex has some inherent readability challenges, it offers more flexibility than Automations' filter: prefix/suffix. This flexibility reduces the number of rules required, simplifying suppression management. Additionally, suppressions should be regularly reviewed, often by someone other than the original author. A well-structured regex rule can still be easier to manage than dozens of fragmented rules in Automations.



.. _reference-implementation:

"Alright, I want this, why is there still more text on this page?"
------------------------------------------------------------------

Well, this is 'just' a lib.
While it provides all the magic you want, why do the standard infra work yourself?
We have a standard implementation of suppressing with this lib available in Terraform
`here <https://github.com/schubergphilis/terraform-aws-mcaf-securityhub-findings-manager>`_.
On top of that, it provides some integrations for automatic alerting and ticketing.

Contents
========

.. toctree::
   :maxdepth: 2

   readme
   installation
   usage
   contributing
   modules
   authors
   history

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
