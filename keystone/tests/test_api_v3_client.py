# -*- coding: utf-8 -*-
"""
    Copyright (C) 2013 Kouhei Maeda <mkouhei@palmtb.net>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import unittest
import sys
import os.path
sys.path.append(os.path.abspath('tests'))
import tests.api_v3_client as c
import tests.test_vars as v


class ApiV3ClientTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.session = c.ApiV3Client(v.base_url_api_v3, v.admin_token, verify=v.verify)

    def test_set_auth_payload_with_domain_name_and_project_name(self):
        self.assertDictEqual(v.auth_payload_domain_name_project_name,
                             c.set_auth_payload(userid=v.user01_userid,
                                                password=v.user01_password,
                                                domain_name=v.default_domain_name,
                                                project_name=v.default_project_name))

    def test_set_auth_payload_with_domain_name_and_project_id(self):
        self.assertDictEqual(v.auth_payload_domain_name_project_id,
                             c.set_auth_payload(userid=v.user01_userid,
                                                password=v.user01_password,
                                                domain_name=v.default_domain_name,
                                                project_id=v.default_project_id))

    def test_set_auth_payload_with_domain_id_and_project_id(self):
        self.assertDictEqual(v.auth_payload_domain_id_project_id,
                             c.set_auth_payload(userid=v.user01_userid,
                                                password=v.user01_password,
                                                domain_id=v.default_domain_id,
                                                project_id=v.default_project_id))

    def test_set_auth_payload_with_domain_id_and_project_name(self):
        self.assertDictEqual(v.auth_payload_domain_id_project_name,
                             c.set_auth_payload(userid=v.user01_userid,
                                                password=v.user01_password,
                                                domain_id=v.default_domain_id,
                                                project_name=v.default_project_name))

    def test_set_auth_payload_with_domain_id(self):
        self.assertDictEqual(v.auth_payload_domain_id,
                             c.set_auth_payload(userid=v.user01_userid,
                                                password=v.user01_password,
                                                domain_id=v.default_domain_id))

    def test_set_auth_payload_with_domain_name(self):
        self.assertDictEqual(v.auth_payload_domain_name,
                             c.set_auth_payload(userid=v.user01_userid,
                                                password=v.user01_password,
                                                domain_name=v.default_domain_name))

    def test_set_auth_payload(self):
        self.assertDictEqual(v.auth_payload,
                             c.set_auth_payload(userid=v.user01_userid,
                                                password=v.user01_password))

    def test_retrieve_id_by_name(self):
        self.assertEqual(v.default_domain_id,
                         c.retrieve_id_by_name(v.test_domains, v.default_domain_name, 'domains'))
