#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
try:
    from pipenv.project import Project
    from pipenv.utils import convert_deps_to_pip

    pfile = Project().parsed_pipfile
    requirements = convert_deps_to_pip(pfile['packages'], r=False)
    test_requirements = convert_deps_to_pip(pfile['dev-packages'], r=False)
except ImportError:
    # get the requirements from the requirements.txt
    requirements = [line.strip()
                    for line in open('requirements.txt').readlines()
                    if line.strip() and not line.startswith('#')]
    # get the test requirements from the test_requirements.txt
    test_requirements = [line.strip()
                         for line in
                         open('dev-requirements.txt').readlines()
                         if line.strip() and not line.startswith('#')]

readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')
version = open('.VERSION').read()


setup(
    name='''awsfindingsmanagerlib''',
    version=version,
    description='''A library to manage findings in AWS.''',
    long_description=readme + '\n\n' + history,
    author='''Marwin Baumann''',
    author_email='''mbaumann@schubergphilis.com''',
    url='''https://github.com/schubergphilis/awsfindingsmanagerlib.git''',
    packages=find_packages(where='.', exclude=('tests', 'hooks', '_CI*')),
    package_dir={'''awsfindingsmanagerlib''':
                 '''awsfindingsmanagerlib'''},
    include_package_data=True,
    install_requires=requirements,
    license='Apache Software License 2.0',
    zip_safe=False,
    keywords='''awsfindingsmanagerlib securityhub findings aws''',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.8',
        ],
    test_suite='tests',
    tests_require=test_requirements
)
