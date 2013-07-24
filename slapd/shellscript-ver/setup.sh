#!/bin/sh

rootdn='cn=admin,dc=example,dc=org'
pw=password
dpkg -l ldap-utils ldapvi > /dev/null 2>&1 || sudo apt-get -y --force-yes ldap-utils ldapvi
dpkg -l slapd > /dev/null 2>&1 && sudo apt-get -y --force-yes purge slapd
sudo debconf-set-selections files/slapd-debconf.txt
sudo DEBCONF_FRONTEND=noninteractive apt-get -y --force-yes install slapd || exit 1
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ../roles/common/files/modify_loglevel.ldif
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ../roles/development/files/rootdnpw_for_test.ldif
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ../roles/development/files/modify_olcAccess.ldif
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ../roles/backend_keystone/files/change_core_schema.ldif
ldapmodify -x -D $rootdn -w $pw -H ldap:// -f ../roles/backend_keystone/files/add_dc_ou_for_keystone.ldif
ldapmodify -x -D $rootdn -w $pw -H ldap:// -f ../roles/backend_keystone/files/add_users.ldif
