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
import requests
sys.path.append(os.path.abspath('tests'))
import tests.api_v3_client as c
import tests.test_vars as v


class ApiV3ClientTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.k = c.ApiV3Client(v.base_url_api_v3, v.admin_token, verify=v.verify)
        self.l = c.LdapClient(v.ldap_url, v.search_base, v.binddn, v.bindpw)

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

    def test_set_api_url(self):
        self.assertEqual(v.domains_url,
                         self.k._set_api_url('domains'))

    def test_set_api_url2(self):
        self.assertEqual(v.domain_url,
                         self.k._set_api_url('domains', 'default'))

    """
    def test_authenticate(self):
        self.assertEqual(1,
                         self.k.authenticate(v.user01_userid,
                                             v.user01_password,
                                             v.default_domain_name,
                                             v.default_project_name))
                                             """

    """
    def test_create_domain(self):
        res = requests.Response()
        res.status_code = 201
        self.assertEqual(res.status_code,
                         self.k.create_domain(v.default_domain_name).status_code)
                         """

    def test_search_entry(self):
        res = self.l.search_entry(v.default_domain_name, v.search_word)
        self.assertTrue(v.domain_entry_dn in res[0][0])
        self.assertListEqual(v.domain_entry_member, res[0][1].get('member'))
        self.assertListEqual(v.domain_entry_description, res[0][1].get('description'))
        self.assertListEqual(v.domain_entry_enabled, res[0][1].get('enabled'))
        self.assertListEqual(v.domain_entry_objectClass, res[0][1].get('objectClass'))
        self.assertListEqual(v.domain_entry_ou, res[0][1].get('ou'))
        self.assertEqual(res[0][0].split(',')[0].split('=')[1], res[0][1].get('cn')[0])
