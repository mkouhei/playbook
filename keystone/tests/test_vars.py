# -*- coding: utf-8 -*-
base_url_api_v3 = 'http://localhost:35357/v3'
ldap_url = 'ldap://localhost'
search_base = 'dc=example,dc=org'
binddn = 'cn=admin,dc=example,dc=org'
bindpw = 'password'
verify = False
admin_token = 'password'
user01_userid = 'user01'
user01_password = 'password'
default_domain_id = 'default'
default_domain_name = 'default'
shared_domain_name = 'shared'
net_domain_name = 'net'
com_domain_name = 'com'
default_project_id = 'default'
default_project_name = 'default'
x_project_name = 'projectx'
y_project_name = 'projecty'
z_project_name = 'projectz'
default_group_id = 'default'
default_group_name = 'default'
x_group_name = 'groupx'
y_group_name = 'groupy'
z_group_name = 'groupz'


a_d_name_p_name = {'auth': {'identity': {'methods': ['password'],
                                         'password': {'user': {'id': 'user01',
                                                               'password': 'pa'
                                                               'ssword'}}},
                            'scope': {'project': {'domain': {'name': 'def'
                                                             'ault'},
                                                  'name': 'default'}}}}

a_d_name_p_id = {'auth': {'identity': {'methods': ['password'],
                                       'password': {'user': {'id': 'user01',
                                                             'password': 'pass'
                                                             'word'}}},
                          'scope': {'project': {'domain': {'name': 'default'},
                                                'id': 'default'}}}}

a_d_id_p_name = {'auth': {'identity': {'methods': ['password'],
                                       'password': {'user': {'id': 'user01',
                                                             'password': 'pass'
                                                             'word'}}},
                          'scope': {'project': {'domain': {'id': 'default'},
                                                'name': 'default'}}}}

a_d_id_p_id = {'auth': {'identity': {'methods': ['password'],
                                     'password': {'user': {'id': 'user01',
                                                           'password': 'pass'
                                                           'word'}}},
                        'scope': {'project': {'domain': {'id': 'default'},
                                              'id': 'default'}}}}

a_d_id = {'auth': {'identity': {'methods': ['password'],
                                'password': {'user': {'domain': {'id': 'defa'
                                                                 'ult'},
                                                      'id': 'user01',
                                                      'password': 'pass'
                                                      'word'}}}}}

a_d_name = {'auth': {'identity': {'methods': ['password'],
                                  'password': {'user': {'domain': {'name': 'd'
                                                                   'efault'},
                                                        'id': 'user01',
                                                        'password': 'pass'
                                                        'word'}}}}}

auth_payload = {'auth': {'identity': {'methods': ['password'],
                                      'password': {'user': {'id': 'user01',
                                                            'password': 'pass'
                                                            'word'}}}}}

test_domains = {'domains': [{'id': 'default', 'name': 'default'},
                            {'id': 'net', 'name': 'net'},
                            {'id': 'com', 'name': 'com'},
                            {'id': 'shared', 'name': 'shared'}]}
test_services = {'services': [{'id': '1111', 'type': 'identity'}]}

domains_url = base_url_api_v3 + '/domains'
domain_url = base_url_api_v3 + '/domains/default'
domain_entry_member = ['cn=dumb,dc=nonexistent']
domain_entry_description = ['default']
domain_entry_enabled = ['TRUE']
domain_entry_objectClass = ['groupOfNames']
domain_entry_ou = ['default']
domain_entry_dn = 'ou=Domains,dc=auth,dc=example,dc=org'
service_id = '1111'
service_type = 'identity'
endpoint_interface = 'internal'
endpoint_name = 'KeyStone Authentication'
endpoint_url = 'http://localhost:35357/v3/'
region = 'regionOne'
admin_role_name = 'admin'
member_role_name = 'member'
credential_type = 'ec2'
credential_blob = {'access': 'hogehoge', 'secret': 'mogemoge'}
