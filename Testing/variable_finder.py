'''
Created on Jun 22, 2013

@author: kshitij
'''
import os
variable = dict()
for root, dirs, files in os.walk('/etc/apparmor.d'):
    for file in files:
        for line in open(os.path.join(root, file), 'r'):
            line.strip()
            if line.startswith('@') and '=' in line:
                line = line.strip()
                line = line.split('=')
                variable[line[0]] = [i.strip('"') for i in line[1].split()] #.strip('"')
for i in variable.keys():
    print(i,variable[i])
                
            