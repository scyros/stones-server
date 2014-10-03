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

import unittest
from utils import BaseTestCase
from model import *


class TestModel(Model):
  prop1 = StringProperty()
  prop2 = IntegerProperty()
  prop3 = FloatProperty()
  prop4 = BooleanProperty()
  prop5 = TextProperty()


class ModelTestCase(BaseTestCase):
  def test_from_dict_string_property_1_ok(self):
    self.assertEqual(TestModel.from_dict({'prop1': 'test'}).prop1, 'test')

  def test_from_dict_string_property_2_ko(self):
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop1': 12}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop1': 12.25}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop1': True}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop1': ['test']}])

  def test_from_dict_integer_property_1_ok(self):
    self.assertEqual(TestModel.from_dict({'prop2': 12}).prop2, 12)
    self.assertEqual(TestModel.from_dict({'prop2': '12'}).prop2, 12)
    self.assertEqual(TestModel.from_dict({'prop2': 12.25}).prop2, 12)

  def test_from_dict_integer_property_2_ko(self):
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop2': True}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop2': [12]}])

  def test_from_dict_float_property_1_ok(self):
    self.assertEqual(TestModel.from_dict({'prop3': 12.25}).prop3, 12.25)
    self.assertEqual(TestModel.from_dict({'prop3': '12.25'}).prop3, 12.25)
    self.assertEqual(TestModel.from_dict({'prop3': 12}).prop3, 12.0)

  def test_from_dict_float_property_2_ko(self):
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop3': True}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop3': [12.25]}])

  def test_from_dict_boolean_property_1_ok(self):
    self.assertEqual(TestModel.from_dict({'prop4': 12}).prop4, True)
    self.assertEqual(TestModel.from_dict({'prop4': '12'}).prop4, True)
    self.assertEqual(TestModel.from_dict({'prop4': 12.25}).prop4, True)
    self.assertEqual(TestModel.from_dict({'prop4': 0}).prop4, False)
    self.assertEqual(TestModel.from_dict({'prop4': 0.0}).prop4, False)
    self.assertEqual(TestModel.from_dict({'prop4': False}).prop4, False)
    self.assertEqual(TestModel.from_dict({'prop4': 'False'}).prop4, False)
    self.assertEqual(TestModel.from_dict({'prop4': 'false'}).prop4, False)
    self.assertEqual(TestModel.from_dict({'prop4': True}).prop4, True)
    self.assertEqual(TestModel.from_dict({'prop4': 'True'}).prop4, True)
    self.assertEqual(TestModel.from_dict({'prop4': 'true'}).prop4, True)

  def test_from_dict_text_property_1_ok(self):
    self.assertEqual(TestModel.from_dict({'prop5': 'test'}).prop5, 'test')

  def test_from_dict_text_property_2_ko(self):
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop5': 12}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop5': 12.25}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop5': True}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop5': ['test']}])
