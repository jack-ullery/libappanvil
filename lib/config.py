import os
import re
import stat

confdir = '/etc/apparmor'
cfg = None
repo_cfg = None

def read_config(filename):
    """Reads the file and returns a double dictionary config[section][attribute]=property"""
    config = dict()
    regex_label = re.compile('^\[(\S+)\]')
    regex_value = re.compile('^\s*(\S+)\s*=\s*(.*)\s*$')
    filepath = confdir + '/' + filename
    try:
        conf_file = open(filepath, 'r', 1)
    except IOError:
        pass
    else:
        section = ''  # The default section
        for line in conf_file:
            # Ignore the comment lines
            if line.lstrip().startswith('#'):       
                continue
            line = line.rstrip('\n')
            # Search for a new section
            label_match = regex_label.search(line)     
            if label_match:
                section = label_match.groups()[0]
            else:
                # Search for a attribute value pair
                value_match = regex_value.search(line)        
                if value_match:
                    attribute = value_match.groups()[0]
                    value = value_match.groups()[1]
                    # A doubly nested dictionary
                    config[section] = config.get(section, {})
                    config[section][attribute] = value
        conf_file.close()
    # LP: Bug #692406
    # Explicitly disabled repository
    if filename == "repository.conf":
        config['repository']={'enabled':'no'}
    return config
        
def write_config(filename, config):
    """Writes the given configuration to the specified file"""
    filepath = confdir + '/' + filename
    try:
        conf_file = open(filepath, 'w') 
    except IOError:
        raise IOError("Unable to write to %s"%filename)
    else:
        for section in sorted(config.iterkeys()):
            # Write the section and all attributes and values under the section
            conf_file.write("[%s]\n"%section)
            for attribute in sorted(config[section].iterkeys()):
                conf_file.write("  %s = %s\n"%(attribute, config[section][attribute]))
        permission_600 = stat.S_IRUSR | stat.S_IWUSR    # Owner read and write
        # Set file permissions as 0600
        os.chmod(filepath, permission_600)
        conf_file.close()

def find_first_file(file_list):
    """Returns name of first matching file None otherwise"""
    # I don't understand why it searches the CWD, maybe I'll find out about it in some module
    filename = None
    if len(file_list):
        for file in file_list.split():
            if os.path.isfile(file):
                filename = file
                break
    return filename

def find_first_dir(dir_list):
    """Returns name of first matching directory None otherwise"""
    dirname = None
    if (len(dir_list)):
        for direc in dir_list.split():
            if os.path.isdir(direc):
                dirname = direc
                break
    return dirname
    