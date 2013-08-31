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
import json
sys.path.append(os.path.abspath('tests'))
import tests.api_v3_client as c
import tests.test_vars as v


class ApiV3ClientTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.k = c.ApiV3Client(v.base_url_api_v3,
                               v.region,
                               verify=v.verify)
        self.l = c.LdapClient(v.ldap_url, v.search_base, v.binddn, v.bindpw)

    def test_set_auth_payload_with_domain_name_and_project_name(self):
        """ OK """
        d = c.set_auth_payload(userid=v.user01_userid,
                               password=v.user01_password,
                               domain_name=v.default_domain_name,
                               project_name=v.default_project_name)
        self.assertDictEqual(v.a_d_name_p_name, d)

    def test_set_auth_payload_with_domain_name_and_project_id(self):
        """ OK """
        d = c.set_auth_payload(userid=v.user01_userid,
                               password=v.user01_password,
                               domain_name=v.default_domain_name,
                               project_id=v.default_project_id)
        self.assertDictEqual(v.a_d_name_p_id, d)

    def test_set_auth_payload_with_domain_id_and_project_id(self):
        """ OK """
        d = c.set_auth_payload(userid=v.user01_userid,
                               password=v.user01_password,
                               domain_id=v.default_domain_id,
                               project_id=v.default_project_id)
        self.assertDictEqual(v.a_d_id_p_id, d)

    def test_set_auth_payload_with_domain_id_and_project_name(self):
        """ OK """
        d = c.set_auth_payload(userid=v.user01_userid,
                               password=v.user01_password,
                               domain_id=v.default_domain_id,
                               project_name=v.default_project_name)
        self.assertDictEqual(v.a_d_id_p_name, d)

    def test_set_auth_payload_with_domain_id(self):
        """ OK """
        self.assertDictEqual(v.a_d_id,
                             c.set_auth_payload(userid=v.user01_userid,
                                                password=v.user01_password,
                                                domain_id=v.default_domain_id))

    def test_set_auth_payload_with_domain_name(self):
        """ OK """
        d = c.set_auth_payload(userid=v.user01_userid,
                               password=v.user01_password,
                               domain_name=v.default_domain_name)
        self.assertDictEqual(v.a_d_name, d)

    def test_set_auth_payload(self):
        """ OK """
        self.assertDictEqual(v.auth_payload,
                             c.set_auth_payload(userid=v.user01_userid,
                                                password=v.user01_password))

    def test_retrieve_id_by_name(self):
        """ OK """
        self.assertEqual(v.default_domain_id,
                         c.retrieve_id_by_name(v.test_domains,
                                               v.default_domain_name,
                                               'domains'))

    def test_retrieve_id_by_type(self):
        """ OK """
        self.assertEqual(v.service_id,
                         c.retrieve_id_by_type(v.test_services,
                                               v.service_type,
                                               'services'))

    def test_set_api_url(self):
        """ OK """
        self.assertEqual(v.domains_url,
                         self.k._set_api_url('domains'))

    def test_set_api_url2(self):
        """ OK """
        self.assertEqual(v.domain_url,
                         self.k._set_api_url('domains', 'default'))

    def test_create_service(self):
        """ OK """
        res = self.k.create_service(token=v.admin_token,
                                    target_type=v.service_type)
        print res.json()
        self.assertEqual(201, res.status_code)
        self.k.delete_service(token=v.admin_token,
                              target_type=v.service_type)

    def test_list_services_none(self):
        """ OK """
        res = self.k.list_services(token=v.admin_token)
        self.assertListEqual([], res.get('services'))

    def test_list_services(self):
        """ OK """
        self.k.create_service(token=v.admin_token,
                              target_type=v.service_type)
        res = self.k.list_services(token=v.admin_token)
        self.assertEqual(1, len(res.get('services')))
        self.assertEqual(v.service_type, res.get('services')[0].get('type'))
        self.k.delete_service(token=v.admin_token,
                              target_type=v.service_type)

    def test_list_services_by_member(self):
        """ OK """
        self.k.create_service(token=v.admin_token,
                              target_type=v.service_type)
        self.l.create_domain(v.net_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.x_project_name,
                              domain_name=v.net_domain_name)
        # prepare role
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.grant_role_user_on_project(token=v.admin_token,
                                          ou_name=v.x_project_name,
                                          target_id=v.user01_userid,
                                          role_name=v.member_role_name)
        res = self.k.authenticate(v.user01_userid,
                                  v.user01_password,
                                  project_name=v.x_project_name,
                                  domain_name=v.net_domain_name)
        print res.status_code
        print 0, res.json()
        print
        print 1, res.headers
        print
        token = res.headers.get('x-subject-token')
        print 2, token
        print
        res = self.k.list_policies(token=token)
        print 3, res
        print
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.x_project_name, 'projects')
        self.k.delete_service(token=v.admin_token,
                              target_type=v.service_type)
        self.l.delete_entry(v.net_domain_name, 'domains')
        #self.assertTrue(False)

    def test_show_service(self):
        """ OK """
        self.k.create_service(token=v.admin_token,
                              target_type=v.service_type)
        res = self.k.show_services(token=v.admin_token,
                                   target_type=v.service_type)
        self.assertEqual(v.service_type, res.json().get('service').get('type'))
        self.k.delete_service(token=v.admin_token,
                              target_type=v.service_type)

    def test_update_service(self):
        """ OK """
        self.k.create_service(token=v.admin_token,
                              target_type=v.service_type)
        res = self.k.show_services(token=v.admin_token,
                                   target_type=v.service_type).json()
        id = res.get('service').get('id')
        payload = {'service': {'id': id, 'type': 'auth'}}
        self.assertEqual(200,
                         self.k.update_service(token=v.admin_token,
                                               target_type=v.service_type,
                                               payload=payload).status_code)
        self.k.delete_service(token=v.admin_token,
                              target_id=id)

    def test_delete_service(self):
        """ OK """
        self.k.create_service(token=v.admin_token,
                              target_type=v.service_type)
        res = self.k.delete_service(token=v.admin_token,
                                    target_type=v.service_type)
        self.assertEqual(204, res.status_code)

    def test_create_endpoint(self):
        """ OK """
        self.k.create_service(token=v.admin_token,
                              target_type=v.service_type)
        res = self.k.create_endpoint(token=v.admin_token,
                                     target_name=v.endpoint_name,
                                     interface=v.endpoint_interface,
                                     url=v.endpoint_url,
                                     service_type=v.service_type)
        self.assertEqual(201, res.status_code)
        self.k.delete_service(token=v.admin_token,
                              target_type=v.service_type)

    def test_list_endpoints_none(self):
        """ OK """
        res = self.k.list_endpoints(token=v.admin_token)
        self.assertListEqual([], res.get('endpoints'))

    def test_list_endpoints(self):
        """ OK """
        self.k.create_service(token=v.admin_token,
                              target_type=v.service_type)
        self.k.create_endpoint(token=v.admin_token,
                               target_name=v.endpoint_name,
                               interface=v.endpoint_interface,
                               url=v.endpoint_url,
                               service_type=v.service_type)
        res = self.k.list_endpoints(token=v.admin_token)
        self.assertEqual(1, len(res.get('endpoints')))
        self.assertEqual(v.endpoint_name, res.get('endpoints')[0].get('name'))
        self.assertEqual(v.endpoint_url, res.get('endpoints')[0].get('url'))
        self.assertEqual(v.endpoint_interface,
                         res.get('endpoints')[0].get('interface'))
        self.k.delete_endpoint(token=v.admin_token,
                               target_name=v.endpoint_name)
        self.k.delete_service(token=v.admin_token,
                              target_type=v.service_type)

    def test_show_endpoint(self):
        """ OK """
        self.k.create_service(token=v.admin_token,
                              target_type=v.service_type)
        self.k.create_endpoint(token=v.admin_token,
                               target_name=v.endpoint_name,
                               interface=v.endpoint_interface,
                               url=v.endpoint_url,
                               service_type=v.service_type)
        res = self.k.show_endpoints(token=v.admin_token,
                                    target_name=v.endpoint_name).json()
        self.assertEqual(v.endpoint_name, res.get('endpoint').get('name'))
        self.assertEqual(v.endpoint_interface,
                         res.get('endpoint').get('interface'))
        self.assertEqual(v.region, res.get('endpoint').get('region'))
        self.assertEqual(v.endpoint_url, res.get('endpoint').get('url'))
        self.k.delete_endpoint(token=v.admin_token,
                               target_name=v.endpoint_name)
        self.k.delete_service(token=v.admin_token,
                              target_type=v.service_type)

    def test_update_endpoint(self):
        """ OK """
        self.k.create_service(token=v.admin_token,
                              target_type=v.service_type)
        self.k.create_endpoint(token=v.admin_token,
                               target_name=v.endpoint_name,
                               interface=v.endpoint_interface,
                               url=v.endpoint_url,
                               service_type=v.service_type)
        res = self.k.show_endpoints(token=v.admin_token,
                                    target_name=v.endpoint_name).json()
        id = res.get('endpoint').get('id')
        payload = {'endpoint': {'id': id, 'interface': 'admin'}}
        self.assertEqual(200,
                         self.k.update_endpoint(token=v.admin_token,
                                                target_id=id,
                                                payload=payload).status_code)
        self.k.delete_endpoint(token=v.admin_token,
                               target_id=id)
        self.k.delete_service(token=v.admin_token,
                              target_type=v.service_type)

    def test_delete_endpoint(self):
        """ OK """
        self.k.create_service(token=v.admin_token,
                              target_type=v.service_type)
        self.k.create_endpoint(token=v.admin_token,
                               target_name=v.endpoint_name,
                               interface=v.endpoint_interface,
                               url=v.endpoint_url,
                               service_type=v.service_type)
        res = self.k.delete_endpoint(token=v.admin_token,
                                     target_name=v.endpoint_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_service(token=v.admin_token,
                              target_type=v.service_type)

    def test_create_credential(self):
        """ Not Implemented """
        self.l.create_domain(v.default_domain_name)
        res = self.k.create_project(token=v.admin_token,
                                    target_name=v.default_project_name)
        project_id = res.json().get('project').get('id')
        res = self.k.create_credential(token=v.admin_token,
                                       target_type=v.credential_type,
                                       target_blob=v.credential_blob,
                                       user_id=v.user01_userid,
                                       project_id=project_id)
        #self.assertEqual(201, res.status_code)
        self.assertEqual(501, res.status_code)
        #self.delete_credential(target_id=credential_id)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_list_credentials(self):
        """ Not implmented """
        creds_l = self.k.list_credentials(
            token=v.admin_token).get('error').get('code')
        self.assertEqual(501, creds_l)

    def test_show_credentials(self):
        """ Not implmented """
        pass

    def test_update_credentials(self):
        """ Not implmented """
        pass

    def test_delete_credentials(self):
        """ Not implmented """
        pass

    def test_create_role(self):
        """ OK """
        res = self.k.create_role(token=v.admin_token,
                                 target_name=v.admin_role_name)
        self.assertEqual(201, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.admin_role_name)

    def test_list_roles_none(self):
        """ OK """
        role_l = self.k.list_roles(token=v.admin_token).get('roles')
        self.assertListEqual([], role_l)

    def test_list_roles(self):
        """ OK """
        self.k.create_role(token=v.admin_token,
                           target_name=v.admin_role_name)
        res = self.k.list_roles(token=v.admin_token).get('roles')
        self.assertEqual(1, len(res))
        self.assertEqual(v.admin_role_name, res[0].get('name'))
        self.k.delete_role(token=v.admin_token,
                           target_name=v.admin_role_name)

    def test_show_role(self):
        """ OK """
        self.k.create_role(token=v.admin_token,
                           target_name=v.admin_role_name)
        res = self.k.show_roles(token=v.admin_token,
                                target_name=v.admin_role_name).json()
        self.assertEqual(v.admin_role_name, res.get('role').get('name'))
        self.k.delete_role(token=v.admin_token,
                           target_name=v.admin_role_name)

    def test_update_role(self):
        """ response is error, but update is succeed.
            TODO: BTS and send patch.
        """
        self.k.create_role(token=v.admin_token,
                           target_name=v.admin_role_name)
        res = self.k.show_roles(token=v.admin_token,
                                target_name=v.admin_role_name).json()
        id = res.get('role').get('id')
        payload = {'role': {'id': id, 'name': 'member'}}
        #self.assertTrue(200, self.k.update_role(token=v.admin_token,
        #                                        target_id=id,
        #                                        payload=payload).status_code)
        self.k.update_role(token=v.admin_token,
                           target_id=id, payload=payload).json()
        res = self.k.show_roles(token=v.admin_token,
                                target_id=id).json()
        self.assertEqual('member', res.get('role').get('name'))
        self.k.delete_role(token=v.admin_token,
                           target_id=id)

    def test_delete_role(self):
        """ OK """
        self.k.create_role(token=v.admin_token,
                           target_name=v.admin_role_name)
        res = self.k.delete_role(token=v.admin_token,
                                 target_name=v.admin_role_name)
        self.assertEqual(204, res.status_code)

    def test_create_domain(self):
        """ OK, but not user API, must use via ldap directory """
        res = self.k.create_domain(token=v.admin_token,
                                   target_name=v.default_domain_name)
        self.assertEqual(201, res.status_code)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_create_domain_via_ldap(self):
        """ OK """
        res = self.l.create_domain(target_name=v.net_domain_name)
        self.assertTupleEqual((105, []), res)
        self.l.delete_entry(v.net_domain_name, 'domains')

    def test_search_entry(self):
        """ OK """
        self.l.create_domain(v.default_domain_name)
        res = self.l.search_entry(v.default_domain_name, 'domains')
        self.assertTrue(v.domain_entry_dn in res[0][0])
        self.assertListEqual(v.domain_entry_member,
                             res[0][1].get('member'))
        self.assertListEqual(v.domain_entry_description,
                             res[0][1].get('description'))
        self.assertListEqual(v.domain_entry_enabled,
                             res[0][1].get('enabled'))
        self.assertListEqual(v.domain_entry_objectClass,
                             res[0][1].get('objectClass'))
        self.assertListEqual(v.domain_entry_ou, res[0][1].get('ou'))
        self.assertEqual(res[0][0].split(',')[0].split('=')[1],
                         res[0][1].get('cn')[0])
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_list_domains(self):
        """ OK """
        self.l.create_domain(v.default_domain_name)
        res = self.k.list_domains(token=v.admin_token)
        self_links = res['domains'][0]['links']['self']
        self.assertEqual(v.default_domain_name,
                         res['domains'][0]['name'])
        self.assertEqual(v.default_domain_name,
                         res['domains'][0]['description'])
        self.assertEqual(True, res['domains'][0]['enabled'])
        self.assertEqual(200,
                         self.k._get(v.admin_token,
                                     self_links).status_code)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_show_domain(self):
        """ OK """
        self.l.create_domain(v.default_domain_name)
        res = self.k.show_domains(token=v.admin_token,
                                  target_name=v.default_domain_name)
        self.assertEqual(v.default_domain_name, res.json()['domain']['name'])
        self.assertEqual(v.default_domain_name,
                         res.json()['domain']['description'])
        self.assertEqual(True, res.json()['domain']['enabled'])
        self.assertEqual(200, res.status_code)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_delete_domain(self):
        """ OK, but this api is not implemented,
            so connect LDAP directly in work around."""
        self.l.create_domain(v.default_domain_name)
        self.assertEqual(107,
                         self.l.delete_entry(v.default_domain_name,
                                             'domains')[0])

    def test_create_project(self):
        """ OK """
        self.l.create_domain(v.default_domain_name)
        res = self.k.create_project(token=v.admin_token,
                                    target_name=v.default_project_name)
        self.assertEqual(201, res.status_code)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_create_project_with_domain(self):
        """ OK """
        self.l.create_domain(v.net_domain_name)
        res = self.k.create_project(token=v.admin_token,
                                    target_name=v.default_project_name,
                                    domain_name=v.net_domain_name)
        self.assertEqual(201, res.status_code)
        self.k.list_domains(token=v.admin_token)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.net_domain_name, 'domains')

    def test_list_projects(self):
        """ OK """
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name)
        res = self.k.list_projects(token=v.admin_token)
        id = res['projects'][0]['id']
        self_links = res['projects'][0]['links']['self']
        self.assertEqual(v.default_project_name,
                         res['projects'][0]['name'])
        self.assertEqual(v.default_project_name,
                         res['projects'][0]['description'])
        self.assertEqual(True, res['projects'][0]['enabled'])
        self.assertEqual(200,
                         self.k._get(v.admin_token,
                                     self_links).status_code)
        self.l.delete_entry(v.default_project_name, 'projects')

    def test_show_project(self):
        """ OK """
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name)
        res = self.k.show_projects(token=v.admin_token,
                                   target_name=v.default_project_name)
        self.assertEqual(v.default_project_name,
                         res.json()['project']['name'])
        self.assertEqual(v.default_project_name,
                         res.json()['project']['description'])
        self.assertEqual(True, res.json()['project']['enabled'])
        self.assertEqual(200, res.status_code)
        self.l.delete_entry(v.default_project_name, 'projects')

    def test_delete_project(self):
        """ OK, but this api is not implemented,
            so connect LDAP directly in work around."""
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name)
        self.assertEqual((107, [], 3, []),
                         self.l.delete_entry(v.default_project_name,
                                             'projects'))

    def test_create_group(self):
        """ OK """
        self.l.create_domain(v.default_domain_name)
        res = self.k.create_group(token=v.admin_token,
                                  target_name=v.default_group_name)
        self.assertEqual(201,
                         res.status_code)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.default_group_name)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_create_group_in_domain(self):
        """ OK """
        self.l.create_domain(v.default_domain_name)
        res = self.k.create_group(token=v.admin_token,
                                  target_name=v.default_group_name,
                                  domain_name=v.default_domain_name)
        self.assertEqual(201, res.status_code)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.default_group_name)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_list_groups(self):
        """ OK """
        self.k.create_group(token=v.admin_token,
                            target_name=v.default_group_name)
        res = self.k.list_groups(token=v.admin_token)
        id = res['groups'][0]['id']
        self_links = res['groups'][0]['links']['self']
        self.assertEqual(v.default_group_name, res['groups'][0]['name'])
        self.assertEqual(v.default_group_name, res['groups'][0]['description'])
        self.assertEqual(v.default_domain_name, res['groups'][0]['domain_id'])
        self.assertEqual(200,
                         self.k._get(v.admin_token,
                                     self_links).status_code)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.default_group_name)

    def test_show_group(self):
        """ OK """
        self.k.create_group(token=v.admin_token,
                            target_name=v.default_group_name)
        res = self.k.show_groups(token=v.admin_token,
                                 target_name=v.default_group_name)
        self.assertEqual(v.default_project_name,
                         res.json()['group']['name'])
        self.assertEqual(v.default_project_name,
                         res.json()['group']['description'])
        self.assertEqual(200, res.status_code)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.default_group_name)

    def test_delete_group(self):
        """ OK """
        self.k.create_group(token=v.admin_token,
                            target_name=v.default_group_name)
        res = self.k.delete_group(token=v.admin_token,
                                  target_name=v.default_group_name)
        self.assertEqual(204, res.status_code)

    def test_list_users(self):
        """ OK """
        users_size = len(self.k.list_users(token=v.admin_token).get('users'))
        self.assertEqual(16, users_size)

    def test_show_users(self):
        """ OK """
        res = self.k.show_users(token=v.admin_token,
                                target_name=v.user01_userid).json()
        self.assertEqual(v.user01_userid, res.get('user').get('id'))

    def test_list_user_projects(self):
        """ fixes #1101287 by changing I449a41e9
            But this method maybe not use. """
        res = self.k.show_users(token=v.admin_token,
                                target_name=v.user01_userid).json()
        userid = res.get('user').get('id')
        res = self.k.list_users(userid, 'projects',
                                token=v.admin_token)
        self.assertListEqual([], res.get('projects'))

    def test_list_user_groups(self):
        """ OK """
        self.l.create_domain(v.default_domain_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.x_group_name,
                            domain_name=v.default_domain_name).json()
        self.k.add_user_to_group(v.user01_userid,
                                 token=v.admin_token,
                                 group_name=v.x_group_name)
        res = self.k.list_users(v.user01_userid, 'groups',
                                token=v.admin_token)
        self.assertTrue(v.user01_userid in res.get('links').get('self'))
        self.k.delete_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_add_user_to_group(self):
        """ OK """
        self.l.create_domain(v.default_domain_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.default_group_name,
                            domain_name=v.default_domain_name).json()
        res = self.k.add_user_to_group(v.user01_userid,
                                       token=v.admin_token,
                                       group_name=v.default_group_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.default_group_name)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_grant_role_user_on_domain(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        res = self.k.grant_role_user_on_domain(token=v.admin_token,
                                               ou_name=v.default_domain_name,
                                               target_id=v.user01_userid,
                                               role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_grant_role_group_on_domain(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.x_group_name)
        res = self.k.grant_role_group_on_domain(token=v.admin_token,
                                                ou_name=v.default_domain_name,
                                                target_name=v.x_group_name,
                                                role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')
        self.k.delete_group(token=v.admin_token,
                            target_name=v.x_group_name)

    def test_list_user_roles_on_domain(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.grant_role_user_on_domain(token=v.admin_token,
                                         ou_name=v.default_domain_name,
                                         target_id=v.user01_userid,
                                         role_name=v.member_role_name)
        res = self.k.list_roles_user_on_domain(token=v.admin_token,
                                               ou_name=v.default_domain_name,
                                               target_id=v.user01_userid)
        role_id = res.json().get('roles')[0].get('id')
        self.assertEqual(200, res.status_code)
        self.assertEqual(32, len(role_id))
        self.assertEqual(v.member_role_name,
                         res.json().get('roles')[0].get('name'))
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_list_group_roles_on_domain(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.k.grant_role_group_on_domain(token=v.admin_token,
                                          ou_name=v.default_domain_name,
                                          target_name=v.x_group_name,
                                          role_name=v.member_role_name)
        res = self.k.list_roles_group_on_domain(token=v.admin_token,
                                                ou_name=v.default_domain_name,
                                                target_name=v.x_group_name)
        self.assertEqual(200, res.status_code)
        self.assertEqual(v.member_role_name,
                         res.json().get('roles')[0].get('name'))
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')
        self.k.delete_group(token=v.admin_token,
                            target_name=v.x_group_name)

    def test_check_user_has_role_on_domain(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.grant_role_user_on_domain(token=v.admin_token,
                                         ou_name=v.default_domain_name,
                                         target_id=v.user01_userid,
                                         role_name=v.member_role_name)
        res = self.k.check_user_has_role_on_domain(
            token=v.admin_token,
            ou_name=v.default_domain_name,
            target_name=v.user01_userid,
            role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_check_group_has_role_on_domain(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.grant_role_group_on_domain(token=v.admin_token,
                                          ou_name=v.default_domain_name,
                                          target_name=v.x_group_name,
                                          role_name=v.member_role_name)
        res = self.k.check_group_has_role_on_domain(
            token=v.admin_token,
            ou_name=v.default_domain_name,
            target_name=v.x_group_name,
            role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_revoke_role_from_user_on_domain(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.grant_role_user_on_domain(token=v.admin_token,
                                         ou_name=v.default_domain_name,
                                         target_id=v.user01_userid,
                                         role_name=v.member_role_name)
        res = self.k.revoke_role_from_user_on_domain(
            token=v.admin_token,
            ou_name=v.default_domain_name,
            target_name=v.user01_userid,
            role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_revoke_role_from_group_on_domain(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.grant_role_group_on_domain(token=v.admin_token,
                                          ou_name=v.default_domain_name,
                                          target_name=v.x_group_name,
                                          role_name=v.member_role_name)
        res = self.k.revoke_role_from_group_on_domain(
            token=v.admin_token,
            ou_name=v.default_domain_name,
            target_name=v.x_group_name,
            role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_grant_role_user_on_project(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        res = self.k.grant_role_user_on_project(token=v.admin_token,
                                                ou_name=v.default_project_name,
                                                target_id=v.user01_userid,
                                                role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_grant_role_group_on_project(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.x_group_name)
        res = self.k.grant_role_group_on_project(
            token=v.admin_token,
            ou_name=v.default_project_name,
            target_name=v.x_group_name,
            role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_list_user_role_on_project(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        print self.k.grant_role_user_on_project(token=v.admin_token,
                                                ou_name=v.default_project_name,
                                                target_id=v.user01_userid,
                                                role_name=v.member_role_name)
        res = self.k.list_roles_user_on_project(
            token=v.admin_token,
            ou_name=v.default_project_name,
            target_name=v.user01_userid)
        print res.json()
        role_id = res.json().get('roles')[0].get('id')
        self.assertEqual(200, res.status_code)
        self.assertEqual(32, len(role_id))
        self.assertEqual(v.member_role_name,
                         res.json().get('roles')[0].get('name'))
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_list_group_role_on_project(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.x_group_name)
        res = self.k.list_roles_group_on_project(
            token=v.admin_token,
            ou_name=v.default_project_name,
            target_name=v.x_group_name)
        self.assertEqual(200, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_check_user_has_role_on_project(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.grant_role_user_on_project(token=v.admin_token,
                                          ou_name=v.default_project_name,
                                          target_id=v.user01_userid,
                                          role_name=v.member_role_name)
        res = self.k.check_user_has_role_on_project(
            token=v.admin_token,
            ou_name=v.default_project_name,
            target_name=v.user01_userid,
            role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_check_group_has_role_on_project(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.grant_role_group_on_project(
            token=v.admin_token,
            ou_name=v.default_project_name,
            target_name=v.x_group_name,
            role_name=v.member_role_name)
        res = self.k.check_group_has_role_on_project(
            token=v.admin_token,
            ou_name=v.default_project_name,
            target_name=v.x_group_name,
            role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_revoke_role_from_user_on_project(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.grant_role_user_on_project(token=v.admin_token,
                                          ou_name=v.default_project_name,
                                          target_id=v.user01_userid,
                                          role_name=v.member_role_name)
        res = self.k.revoke_role_from_user_on_project(
            token=v.admin_token,
            ou_name=v.default_project_name,
            target_name=v.user01_userid,
            role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_revoke_role_from_group_on_project(self):
        """ fixes #1101287 by changing I449a41e9 """
        self.l.create_domain(v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.grant_role_group_on_project(token=v.admin_token,
                                           ou_name=v.default_project_name,
                                           target_name=v.x_group_name,
                                           role_name=v.member_role_name)
        res = self.k.revoke_role_from_group_on_project(
            token=v.admin_token,
            ou_name=v.default_project_name,
            target_name=v.x_group_name,
            role_name=v.member_role_name)
        self.assertEqual(204, res.status_code)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.x_group_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_list_effective_role_assignments(self):
        """ not yet tested """
        print self.k.get_role_assginments(token=v.admin_token)
        #self.assertTrue(False)

    def test_create_policy(self):
        """ OK """
        res = self.k.create_policy(token=v.admin_token,
                                   target_blob=v.policy_blob,
                                   target_type=v.policy_mimetype)
        self.assertEqual(201, res.status_code)
        self.k.delete_policy(token=v.admin_token,
                             target_blob=v.policy_blob)

    def test_list_policies_none(self):
        """ OK """
        res = self.k.list_policies(token=v.admin_token)
        self.assertEqual(0, len(res.get('policies')))

    def test_list_policies(self):
        """ OK """
        self.k.create_policy(token=v.admin_token,
                             target_blob=v.policy_blob,
                             target_type=v.policy_mimetype)
        self.k.create_policy(token=v.admin_token,
                             target_blob=v.policy_blob2,
                             target_type=v.policy_mimetype)
        res = self.k.list_policies(token=v.admin_token)
        self.assertEqual(2, len(res.get('policies')))
        self.k.delete_policy(token=v.admin_token,
                             target_blob=v.policy_blob)
        self.k.delete_policy(token=v.admin_token,
                             target_blob=v.policy_blob2)

    def test_show_policies(self):
        """ OK """
        self.k.create_policy(token=v.admin_token,
                             target_blob=v.policy_blob,
                             target_type=v.policy_mimetype)
        res = self.k.show_policies(token=v.admin_token,
                                   target_blob=v.policy_blob)
        self.assertEqual(200, res.status_code)
        self.k.delete_policy(token=v.admin_token,
                             target_blob=v.policy_blob)

    def test_update_policy(self):
        """ OK """
        self.k.create_policy(token=v.admin_token,
                             target_blob=v.policy_blob,
                             target_type=v.policy_mimetype)
        res = self.k.show_policies(token=v.admin_token,
                                   target_blob=v.policy_blob)
        payload = res.json()
        print payload
        policy_id = payload.get('policy').get('id')
        payload['policy']['blob'] = v.policy_blob2
        res = self.k.update_policy(token=v.admin_token,
                                   target_id=policy_id,
                                   payload=payload)
        self.assertEqual(200, res.status_code)
        print self.k.delete_policy(token=v.admin_token,
                                   target_id=policy_id)

    def test_delete_policies(self):
        """ OK """
        self.k.create_policy(token=v.admin_token,
                             target_blob=v.policy_blob,
                             target_type=v.policy_mimetype)
        res = self.k.show_policies(token=v.admin_token,
                                   target_blob=v.policy_blob)
        policy_id = res.json().get('policy').get('id')
        res = self.k.delete_policy(token=v.admin_token,
                                   target_id=policy_id)
        self.assertEqual(204, res.status_code)

    def test_authenticate_hoge(self):
        # domain id must be same businessCategory
        # and be unique name and not using uuid
        self.l.create_domain(v.net_domain_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.default_group_name,
                            domain_name=v.net_domain_name)
        self.k.add_user_to_group(v.user01_userid,
                                 token=v.admin_token,
                                 group_name=v.default_group_name)
        res = self.k.authenticate(v.user01_userid,
                                  v.user01_password,
                                  domain_name=v.net_domain_name)
        self.assertEqual(201, res.status_code)
        self.assertEqual(32, len(res.headers.get('x-subject-token')))
        self.k.delete_group(token=v.admin_token,
                            target_name=v.default_group_name)
        self.l.delete_entry(v.net_domain_name, 'domains')

    def test_validate_token(self):
        # domain id must be same businessCategory
        # and be unique name and not using uuid
        self.l.create_domain(v.net_domain_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.default_group_name,
                            domain_name=v.net_domain_name)
        self.k.add_user_to_group(v.user01_userid,
                                 token=v.admin_token,
                                 group_name=v.default_group_name)
        res = self.k.authenticate(v.user01_userid,
                                  v.user01_password,
                                  domain_name=v.net_domain_name)
        subject_token = res.headers.get('x-subject-token')
        self.assertEqual(200,
                         self.k.validate_token(subject_token,
                                               v.admin_token).status_code)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.default_group_name)
        self.l.delete_entry(v.net_domain_name, 'domains')

    def test_check_token(self):
        # domain id must be same businessCategory
        # and be unique name and not using uuid
        self.l.create_domain(v.net_domain_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.default_group_name,
                            domain_name=v.net_domain_name)
        self.k.add_user_to_group(v.user01_userid,
                                 token=v.admin_token,
                                 group_name=v.default_group_name)
        res = self.k.authenticate(v.user01_userid,
                                  v.user01_password,
                                  domain_name=v.net_domain_name)
        subject_token = res.headers.get('x-subject-token')
        self.assertEqual(204,
                         self.k.check_token(subject_token,
                                            v.admin_token).status_code)
        self.k.delete_group(token=v.admin_token,
                            target_name=v.default_group_name)
        self.l.delete_entry(v.net_domain_name, 'domains')

    def test_revoke_token(self):
        # domain id must be same businessCategory
        # and be unique name and not using uuid
        self.l.create_domain(v.net_domain_name)
        self.k.create_group(token=v.admin_token,
                            target_name=v.default_group_name,
                            domain_name=v.net_domain_name)
        self.k.add_user_to_group(v.user01_userid,
                                 token=v.admin_token,
                                 group_name=v.default_group_name)
        res = self.k.authenticate(v.user01_userid,
                                  v.user01_password,
                                  domain_name=v.net_domain_name)
        subject_token = res.headers.get('x-subject-token')
        self.assertEqual(200,
                         self.k.validate_token(subject_token,
                                               v.admin_token).status_code)
        res = self.k.revoke_token(subject_token, v.admin_token)
        self.assertEqual(204, res.status_code)
        res = self.k.validate_token(subject_token,
                                    v.admin_token).json()
        self.assertTrue('Could not find token'
                        in res.get('error').get('message'))
        #self.assertTrue('The request you have made requires authentication'
        #                in res.get('error').get('message'))
        self.k.delete_group(token=v.admin_token,
                            target_name=v.default_group_name)
        self.l.delete_entry(v.net_domain_name, 'domains')

    def test_authenticate_with_adminuser_over_crossdomain(self):
        """ OK """
        # domain id must be same businessCategory
        # and be unique name and not using uuid.

        # prepare domain, project
        self.l.create_domain(v.default_domain_name)
        self.l.create_domain(v.net_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.default_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.x_project_name,
                              domain_name=v.net_domain_name)

        # prepare role
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.admin_role_name)

        # grant role to user
        self.k.grant_role_user_on_project(token=v.admin_token,
                                          ou_name=v.x_project_name,
                                          target_id=v.user01_userid,
                                          role_name=v.member_role_name)

        self.k.grant_role_user_on_project(token=v.admin_token,
                                          ou_name=v.default_project_name,
                                          target_id=v.admin_userid,
                                          role_name=v.admin_role_name)

        # authenticate member
        res = self.k.authenticate(v.user01_userid,
                                  v.user01_password,
                                  project_name=v.x_project_name,
                                  domain_name=v.net_domain_name)
        token_member = res.headers.get('x-subject-token')
        self.assertNotEqual(None, token_member)

        # for admin user
        res = self.k.authenticate(v.admin_userid,
                                  v.admin_password,
                                  project_name=v.default_project_name,
                                  domain_name=v.default_domain_name)
        token_admin = res.headers.get('x-subject-token')
        self.assertNotEqual(None, token_admin)

        # validation
        res = self.k.validate_token(token_member, token_admin)
        self.assertEqual(token_member, res.headers['x-subject-token'])
        self.assertEqual(200, res.status_code)
        self.assertEqual(32, len(res.headers.get('x-subject-token')))
        self.k.delete_role(token=v.admin_token,
                           target_name=v.admin_role_name)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.x_project_name, 'projects')
        self.l.delete_entry(v.net_domain_name, 'domains')
        self.l.delete_entry(v.default_domain_name, 'domains')

    def test_authenticate_with_adminuser_in_samedomain(self):
        # not OK
        # domain id must be same businessCategory
        # and be unique name and not using uuid.

        # authenticate() arguments of admin user
        # without both: authenticate is OK, validate is not authorized.
        #    -> must fix validate byself.
        # project_name and domain_name:
        #    -> I'd implemented get_domain_by_name().
        #    -> authenticate is OK, validate is not authorized.
        # project_name only: Expecting to find domain in project.
        #    -> require project and domain.
        # domain_name only: authenticate is OK, validate is not authorized.
        #    -> must fix validate byself.

        # prepare domain, project
        self.l.create_domain(v.net_domain_name)
        self.k.create_project(token=v.admin_token,
                              target_name=v.default_project_name,
                              domain_name=v.net_domain_name)

        # prepare role
        self.k.create_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.k.create_role(token=v.admin_token,
                           target_name=v.admin_role_name)

        # grant role to user
        self.k.grant_role_user_on_project(token=v.admin_token,
                                          ou_name=v.default_project_name,
                                          target_id=v.user01_userid,
                                          role_name=v.member_role_name)

        self.k.grant_role_user_on_project(token=v.admin_token,
                                          ou_name=v.default_project_name,
                                          target_id=v.user02_userid,
                                          role_name=v.admin_role_name)
        """
        self.k.grant_role_user_on_domain(token=v.admin_token,
                                         ou_name=v.net_domain_name,
                                         target_id=v.user02_userid,
                                         role_name=v.admin_role_name)
                                         """
        # authenticate member
        res = self.k.authenticate(v.user01_userid,
                                  v.user01_password,
                                  project_name=v.default_project_name,
                                  domain_name=v.net_domain_name)
        token_member = res.headers.get('x-subject-token')
        self.assertNotEqual(None, token_member)

        # authenticate admin
        res = self.k.authenticate(v.user02_userid,
                                  v.user02_password,
                                  project_name=v.default_project_name,
                                  domain_name=v.net_domain_name)
        token_admin = res.headers.get('x-subject-token')
        self.assertNotEqual(None, token_admin)
        res = self.k.validate_token(token_member, token_admin)
        self.assertEqual(token_member, res.headers['x-subject-token'])
        self.assertEqual(200, res.status_code)
        self.assertEqual(32, len(res.headers.get('x-subject-token')))
        self.k.delete_role(token=v.admin_token,
                           target_name=v.admin_role_name)
        self.k.delete_role(token=v.admin_token,
                           target_name=v.member_role_name)
        self.l.delete_entry(v.default_project_name, 'projects')
        self.l.delete_entry(v.net_domain_name, 'domains')
