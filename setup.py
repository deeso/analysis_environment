#!/usr/bin/env python3
from setuptools import setup, find_packages
# configure the setup to install from specific repos and users

DESC = 'analysis workspace for simplicity'
setup(name='analysis-workspace',
      version='1.0',
      description=DESC,
      author='adam pridgen',
      author_email='dso@thecoverofnight.com',
      install_requires=['gglsbl', 'virustotal-api',
                        'pymongo', 'requests',
                        'ipython', 'matplotlib', 'scapy', 'dpkt',
                        'dnspython', ],
      packages=find_packages('src'),
      package_dir={'': 'src'},
      dependency_links=[],
      )


