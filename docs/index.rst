.. awsfindingsmanagerlib documentation master file, created by
   sphinx-quickstart on 2023-11-21.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

awsfindingsmanagerlib
*********************

*Focus on what matters.*

Automated scanning and finding consolidation is a cornerstone in evaluating your security posture.
AWS Security Hub is the native solution to preform this in job in AWS.
As with any scanning and reporting tool, the amount of findings it generates can be overwhelming at first.
Also, you may find that some findings are not relevant or have less urgency to fix in your specific situation.

**awsfindingsmanagerlib** suppresses findings based on a ruleset you define.

Quickstart
==========

Install with your favorite Python package manager like::

  pip install awsfindingsmanagerlib

Define what you don't want to bother you anymore, for example:

.. code-block:: yaml

  Rules:
    - note: Mom said it's okay to ignore
      action: SUPPRESSED
      match_on:
        security_control_id: GuardDuty.1

Save and serve your ruleset, for example locally as ``suppressions.yaml`` and with ``python3 -m http.server``.
(More logical/advanced ways of getting your suppressions to your findings manager are covered later.)
Then you should be able to run the following Python code;
provided your AWS credentials allow
``ec2:DescribeRegions``, ``securityhub:GetFindings`` and ``securityhub:BatchUpdateFindings``.

.. code-block:: python

  from awsfindingsmanagerlib import FindingsManager, Http

  http_backend = Http('http://localhost:8000/suppressions.yaml')

  findings_manager = FindingsManager('eu-west-1')
  findings_manager.register_rules(http_backend.get_rules())
  findings_manager.suppress_matching_findings()

And zip 🤐 all noise is silenced.

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

"I use Splunk, Datadog, OpenSearch, AWS Security Hub Automations etc., instead"
-------------------------------------------------------------------------------

The tools above can be divided in AWS Security Hub Automations and third-party tooling.
We think this lib provides something both categories do not offer.
First, we'll cover third-party tooling.

It's generally a good idea to handle an event as close to the source as possible.
Therefore, we think it's better to suppress findings in AWS Security Hub instead of filtering in third-party tooling.
There is certainly something to be said for creating aggregation views in such tools, especially in a multi-cloud environment.
Still, you will more easily create a comprehensive view in any third-party tool if only the relevant data is sent there.
On top of that, it will save save you money from storage and increase your search speed.

AWS Security Hub Automations is AWS' native solution for exactly the same job as this lib.
However, we think this lib provides usability features that make it a better choice.
Most importantly, this lib allows you to suppress based on multiple combinations of property values in one rule.
As in the example above, you can suppress a single check for multiple resources.
In Automations this would require multiple rules.

Maybe a counter-intuitive strong point of this lib is that the resource matching supports regex.
Regex has its obvious readability issues, but it's far more flexible than Automations' filter: prefix/suffix.
Imagine want to suppress for a resource collection in your dev/test accounts.
With regex you can write something like:
`arn:aws:lambda:eu-central-1:(1234567890|2345678901):function:(client-a|client-b|client-c)`
With Automations you would have to write multiple rules for this.

Observant readers will realize that up until now we only listed readability issues.
We think that readability is a big thing, especially because suppressions should be regularly reviewed.
Those reviews are likely carried out by someone else than the one who wrote them.

Not convinced by readability alone?
Automations has a 100 rule limit.
That limit fills up quickly if you have to a rule for every permutation without support for regex and multiple property combination.
In an organization's audit account it's probably impossible to work with.

Finally, this lib can suppress findings from the past if you want.
Automations can only work with findings in the future.
With this lib you don't have to wait the 90 days findings retention time before your dashboard stops blaring at you.

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

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
