#!/usr/bin/env python

from distutils.core import setup

setup(name='vitz',
      version='0.1',
      description='Contrast trace visualization and debugging tools.',
      url='https://bitbucket.org/contrastsecurity/vizt',
      author='Dan Amodio',
      author_email='dan.amodio@contrastsecurity.com',
      license='',
      packages=['vizt'],
      scripts=['bin/vizt'])