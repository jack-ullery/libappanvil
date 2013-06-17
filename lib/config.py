import os
import stat
import configparser

confdir = '/etc/apparmor'
cfg = None
repo_cfg = None

def read_config(filename):
    """Reads the file and returns a configparser config[section][attribute]=property"""
    config = configparser.ConfigParser()
    filepath = confdir + '/' + filename
    config.read(filepath)
    # LP: Bug #692406
    # Explicitly disabled repository
    if filename == "repository.conf":
        config['repository'] = {'enabled': 'no'}
    return config
        
def write_config(filename, config):
    """Writes the given configparser to the specified file"""
    filepath = confdir + '/' + filename
    try:
        with open(filepath, 'w') as config_file:
            config.write(config_file) 
    except IOError:
        raise IOError("Unable to write to %s"%filename)
    else:
        permission_600 = stat.S_IRUSR | stat.S_IWUSR    # Owner read and write
        # Set file permissions as 0600
        os.chmod(filepath, permission_600)

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
    