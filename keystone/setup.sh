#!/bin/sh

# for simple playbook
#ansible-playbook -K -v -i hosts simple-setup-test.yml

ansible-playbook -K -v -i hosts site.yml
