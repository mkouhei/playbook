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


auth_payload_domain_name_project_name = {'auth': {'identity': {'methods': ['password'],
                                                               'password': {'user': {'id': 'user01',
                                                                                     'password': 'password'}}},
                                                  'scope': {'project': {'domain': {'name': 'default'},
                                                                        'name': 'default'}}}}

auth_payload_domain_name_project_id = {'auth': {'identity': {'methods': ['password'],
                                                             'password': {'user': {'id': 'user01',
                                                                                   'password': 'password'}}},
                                                'scope': {'project': {'domain': {'name': 'default'},
                                                                      'id': 'default'}}}}

auth_payload_domain_id_project_name = {'auth': {'identity': {'methods': ['password'],
                                                             'password': {'user': {'id': 'user01',
                                                                                   'password': 'password'}}},
                                                  'scope': {'project': {'domain': {'id': 'default'},
                                                                        'name': 'default'}}}}

auth_payload_domain_id_project_id = {'auth': {'identity': {'methods': ['password'],
                                                           'password': {'user': {'id': 'user01',
                                                                                 'password': 'password'}}},
                                              'scope': {'project': {'domain': {'id': 'default'},
                                                                    'id': 'default'}}}}

auth_payload_domain_id = {'auth': {'identity': {'methods': ['password'],
                                                'password': {'user': {'domain': {'id': 'default'},
                                                                      'id': 'user01',
                                                                      'password': 'password'}}}}}

auth_payload_domain_name = {'auth': {'identity': {'methods': ['password'],
                                                  'password': {'user': {'domain': {'name': 'default'},
                                                                        'id': 'user01',
                                                                        'password': 'password'}}}}}

auth_payload = {'auth': {'identity': {'methods': ['password'],
                                      'password': {'user': {'id': 'user01',
                                                            'password': 'password'}}}}}

test_domains = {'domains': [{'id': 'default', 'name': 'default'},
                            {'id': 'net', 'name': 'net'},
                            {'id': 'com', 'name': 'com'},
                            {'id': 'shared', 'name': 'shared'}]}

domains_url = base_url_api_v3 + '/domains'
domain_url = base_url_api_v3 + '/domains/default'
target_domain = 'domains'
target_project = 'projects'
target_group = 'groups'
domain_entry_member = ['cn=dumb,dc=nonexistent']
domain_entry_description = ['default']
domain_entry_enabled = ['TRUE']
domain_entry_objectClass = ['groupOfNames']
domain_entry_ou = ['default']
domain_entry_dn = 'ou=Domains,dc=auth,dc=example,dc=org'
