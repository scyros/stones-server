#!/usr/bin/env python
#-*- coding: utf-8 -*-

# This file is part of Stones Server Side.

# Stones Server Side is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Stones Server Side is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Stones Server Side.  If not, see <http://www.gnu.org/licenses/>.

# Copyright 2013, Carlos León <carlos.eduardo.leon.franco@gmail.com>

import optparse
import sys
import os
import logging
# Install the Python unittest2 package before you run this script.
import unittest

USAGE = """%prog SDK_PATH TEST_PATH
Run unit tests for Stones Server.

SDK_PATH    Path to the SDK installation
TEST_PATH   Path to package containing test modules"""

current_path = os.path.abspath(os.path.dirname(__file__))
logging.basicConfig()


def fix_sys_path():
  try:
    from dev_appserver import fix_sys_path as dev_appserver_fix_path
    dev_appserver_fix_path()
  except ImportError, e:
    pass


def main(sdk_path, test_path):
  sys.path.insert(0, sdk_path)
  fix_sys_path()
  os.environ['__APP_TESTING__'] = 'Testing...'
  os.environ['SERVER_SOFTWARE'] = 'Dev'
  suite = unittest.loader.TestLoader().discover(test_path)
  unittest.TextTestRunner(verbosity=2).run(suite)


if __name__ == '__main__':
  parser = optparse.OptionParser(USAGE)
  options, args = parser.parse_args()
  if len(args) != 1:
    print 'Error: Exactly 1 arguments required.'
    parser.print_help()
    sys.exit(1)
  SDK_PATH = args[0]
  TEST_PATH = os.path.join(current_path, 'test')
  main(SDK_PATH, TEST_PATH)
