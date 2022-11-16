#!/bin/python3
# -*- coding: utf-8 -*-
# this script will be used on linux system to use ufw firewall

import os
import sys
import re
import datetime
# To                         Action      From
# --                         ------      ----
# 9443/tcp                   ALLOW       Anywhere
# 8000/tcp                   ALLOW       Anywhere

__author__ = 'Satcom'


def printwt(msg):
    """
    It takes a string as input, and prints it out with a timestamp.
    
    :param msg: The message to print
    """
    print(f'[{datetime.datetime.now()}] {msg}')


def get_allowed_ports():
    """
    It takes the output of the command `sudo ufw status` and returns a list of all the ports that are
    allowed
    :return: A list of ports that are allowed by the firewall.
    """
    ips = []
    # Running the command `sudo ufw status` and storing the output in a variable called `ufw_status`.
    ufw_status = os.popen('sudo ufw status').read()

    # Getting all the ports that are allowed by the firewall.
    x2 = re.findall(r'(\d+\/\w+)\s+ALLOW', ufw_status)
    # Getting all the ports that are allowed by the firewall.
    x1 = re.findall(r'(\d+\w+)\s+ALLOW', ufw_status)
    allowed_ports = x1 + x2

    for port in allowed_ports:
        ips.append(port)
    return ips


def get_deleted_ports():
    """
    It takes the output of the command `sudo ufw status` and searches for all the ports that have been
    deleted from the firewall
    :return: A list of ports that have been deleted from the firewall.
    """
    ips = []
    # Running the command `sudo ufw status` and storing the output in a variable called `ufw_status`.
    ufw_status = os.popen('sudo ufw status').read()
    # Getting all the ports that have been deleted from the firewall.
    deleted_ports = re.findall(r'(\d+\/\w+)\s+DENY', ufw_status)

    for port in deleted_ports:
        ips.append(port)
    return ips


def is_port_used(port):
    """
    It checks if the port is used by any process
    
    :param port: The port number to check
    :return: True or False
    """
    # Splitting the port into two parts, the port number and the protocol.
    port, protocol = port.split('/') if re.search(r'\/', port) else (port,
                                                                     'tcp')
    # Using the command `sudo lsof -i:{port}` to check if the port is used by any process.
    used_ports = re.findall(rf'{port}',
                            os.popen(f'sudo lsof -i:{port}').read())
    return True if used_ports else False


def main():
    """
    It reads the whitelist.txt file, gets the allowed ports from the firewall, checks if the ports are
    used, and if they are not used, it checks if they are whitelisted, and if they are not whitelisted,
    it deletes them from the firewall
    """
    # Reading the whitelist.txt file and storing the contents in a list called whitelist.
    with open('whitelist.txt', 'r') as f:
        whitelist = f.read().splitlines()

    # Getting all the ports that are allowed by the firewall, and checking if they are used by any
    # process. If they are not used, it adds them to a list called port_to_delete.
    port_to_delete = []
    allowed_ips = get_allowed_ports()
    for port in allowed_ips:
        if is_port_used(port):
            print(f'{port} is used')
        else:
            print(f'port {port} is not used')
            port_to_delete.append(port)

    # Checking if the port is whitelisted, and if it is whitelisted, it removes it from the list of
    # ports to delete.
    for port in whitelist:
        for port_to_del in port_to_delete:
            if re.search(rf'^{port}\/\w+', port_to_del) or re.search(
                    rf'^{port}$', port_to_del):
                port_to_delete.remove(port_to_del)
                print(f'{port_to_del} is whitelisted and will not be deleted')
    v = input('do you want to delete these ports from firewall? (y/n)')

    # Deleting the ports from the firewall.
    if v == 'Y':
        for port in port_to_delete:
            os.system('sudo ufw delete allow {}'.format(port))
            printwt(f'{port} deleted from firewall')
    else:
        printwt('no ports deleted')
        os.system('sudo ufw status')
        print(f"Thanks for using this script, bye bye !")
        exit()


if __name__ == '__main__':
    main()