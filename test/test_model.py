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
import datetime
from utils import BaseTestCase
from model import *


class TestModel(Model):
  prop1 = StringProperty()
  prop2 = IntegerProperty()
  prop3 = FloatProperty()
  prop4 = BooleanProperty()
  prop5 = TextProperty()
  prop6 = BlobProperty()
  prop7 = JsonProperty()
  prop8 = DateProperty()
  prop9 = DateTimeProperty()
  prop10 = TimeProperty()
  prop11 = KeyProperty()


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

  def test_from_dict_blob_property_1_ok(self):
    self.assertEqual(TestModel.from_dict({'prop6': 'test'}).prop6, 'test')

  def test_from_dict_blob_property_2_ko(self):
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop6': 12}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop6': 12.25}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop6': True}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop6': ['test']}])

  def test_from_dict_json_property_1_ok(self):
    self.assertEqual(TestModel.from_dict({'prop7': {'key': 'value'}}).prop7,
                     {'key': 'value'})

  def test_from_dict_json_property_2_ko(self):
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop7': 12}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop7': 12.25}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop7': True}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop7': ['test']}])

  def test_from_dict_date_property_1_ok(self):
    value = '2014-10-06' #T20:10:34Z'
    date = datetime.datetime.strptime(value, DATE_FORMAT).date()
    self.assertEqual(TestModel.from_dict({'prop8': value}).prop8, date)

  def test_from_dict_date_property_2_ko(self):
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop8': 12}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop8': 12.25}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop8': True}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop8': ['test']}])

  def test_from_dict_datetime_property_1_ok(self):
    value = '2014-10-06T20:10:34Z'
    date = datetime.datetime.strptime(value, DATETIME_FORMAT)
    self.assertEqual(TestModel.from_dict({'prop9': value}).prop9, date)

  def test_from_dict_datetime_property_2_ko(self):
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop9': 12}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop9': 12.25}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop9': True}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop9': ['test']}])

  def test_from_dict_time_property_1_ok(self):
    value = '20:10:34'
    time = datetime.datetime.strptime(value, TIME_FORMAT).time()
    self.assertEqual(TestModel.from_dict({'prop10': value}).prop10, time)

  def test_from_dict_time_property_2_ko(self):
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop10': 12}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop10': 12.25}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop10': True}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop10': ['test']}])

  def test_from_dict_key_property_1_ok(self):
    entity = TestModel()
    key = entity.put()
    self.assertEqual(TestModel.from_dict({'prop11': key.urlsafe()}).prop11, key)
    self.assertEqual(TestModel.from_dict(
      {'prop11': {'__key__': key.urlsafe()}}).prop11, key)
    self.assertEqual(TestModel.from_dict(
      {'prop11': {'urlsafe_key': key.urlsafe()}}).prop11, key)

  def test_from_dict_key_property_2_ko(self):
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop11': 12}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop11': 12.25}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop11': True}])
    self.assertRaises(datastore_errors.BadValueError, TestModel.from_dict,
                      *[{'prop11': ['test']}])
