import configparser
import os
import shutil
import stat
import tempfile


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
    permission_600 = stat.S_IRUSR | stat.S_IWUSR    # Owner read and write
    try:
        # Open a temporary file to write the config file
        config_file = tempfile.NamedTemporaryFile('w', prefix='aa_temp', delete=False)
        # Set file permissions as 0600
        os.chmod(config_file.name, permission_600)
        config.write(config_file)
        config_file.close()
    except IOError:
        raise IOError("Unable to write to %s"%filename)
    else:
        # Move the temporary file to the target config file
        shutil.move(config_file.name, filepath)
        

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
    