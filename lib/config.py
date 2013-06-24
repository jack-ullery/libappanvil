import configparser
import os
import shlex
import shutil
import stat
import tempfile


confdir = '/etc/apparmor'
cfg = None
repo_cfg = None
shell_files = ['easyprof.conf', 'notify.conf', 'parser.conf', 'subdomain.conf']

def read_config(filename, conf_type=None):
    """Reads the file and returns a config[section][attribute]=property object"""   
    # LP: Bug #692406
    # Explicitly disabled repository
    filepath = confdir + '/' + filename
    if filename == "repository.conf":
        config = dict()
        config['repository'] = {'enabled': 'no'}
    elif filename in shell_files or conf_type == 'shell':
        config = read_shell(filepath)
    else:
        config = configparser.ConfigParser()
        config.optionxform = str
        config.read(filepath)      
    return config
        
def write_config(filename, config, conf_type=None):
    """Writes the given config to the specified file"""
    filepath = confdir + '/' + filename
    permission_600 = stat.S_IRUSR | stat.S_IWUSR    # Owner read and write
    try:
        # Open a temporary file in the confdir to write the config file
        config_file = tempfile.NamedTemporaryFile('w', prefix='aa_temp', delete=False, dir=confdir)
        if os.path.exists(filepath):
            # Copy permissions from an existing file to temporary file
            shutil.copymode(filepath, config_file.name)
        else:
            # If no existing permission set the file permissions as 0600
            os.chmod(config_file.name, permission_600)
            write_shell(filepath, config_file, config)
        if filename in shell_files or conf_type == 'shell':
            write_shell(filepath, config_file, config)
        else:
            write_configparser(filepath, config_file, config)
        #config.write(config_file)
        config_file.close()
    except IOError:
        raise IOError("Unable to write to %s"%filename)
    else:
        # Replace the target config file with the temporary file
        os.rename(config_file.name, filepath)
        

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

def read_shell(filepath):
    """Reads the shell type conf files and returns config[''][option]=value"""
    config = {'': dict()}
    with open(filepath, 'r') as file:
        for line in file:
            result = shlex.split(line, True)
            # If not a comment of empty line
            if result != []:
                # option="value" or option=value type
                if '=' in result[0]:
                    option, value = result[0].split('=')
                # option type
                else:
                    option = result[0]
                    value = None
                config[''][option] = value
    return config

def write_shell(filepath, f_out, config):
    """Writes the config object in shell file format"""
    # All the options in the file
    options = [key for key in config[''].keys()]
    # If a previous file exists modify it keeping the comments
    if os.path.exists(filepath):
        with open(filepath, 'r') as f_in:
            for line in f_in:
                result = shlex.split(line, True)
                # If line is not empty or comment
                if result != []:
                    # If option=value or option="value" type
                    if '=' in result[0]:
                        option, value = result[0].split('=') 
                        # If option exists in the new config file       
                        if option in options:
                            # If value is different
                            if value != config[''][option]:
                                value_new = config[''][option]
                                if value_new != None:
                                    # Update value
                                    if '"' in line:
                                        value_new = '"' + value_new + '"'
                                    line = option + '=' + value_new + '\n'
                                else:
                                    # If option changed to option type from option=value type
                                    line = option + '\n'
                            f_out.write(line)
                            # Remove from remaining options list
                            options.remove(option)
                    else:
                        # If option type
                        option = result[0]
                        value = None
                        # If option exists in the new config file  
                        if option in options:
                            # If its no longer option type
                            if config[''][option] != None:
                                value = config[''][option]
                                line = option + '=' + value + '\n'
                            f_out.write(line)
                            # Remove from remaining options list
                            options.remove(option)             
                else:
                    # If its empty or comment copy as it is
                    f_out.write(line)
    # If any new options are present
    if options != []:
        for option in options:
            value = config[''][option]
            # option type entry
            if value == None:
                line = option + '\n'
            # option=value type entry
            else:
                line = option + '=' + value + '\n'
            f_out.write(line)

def write_configparser(filepath, f_out, config):
    # All the sections in the file
    sections = config.sections()
    write = True
    section = None
    options = []
    # If a previous file exists modify it keeping the comments
    if os.path.exists(filepath):
        with open(filepath, 'r') as f_in:
            for line in f_in:
                # If its a section
                if line.lstrip().startswith('['):
                    # If any options from preceding section remain write them
                    if options != []:
                        for option in options:
                            line_new = '  ' + option + ' = ' + config[section][option] + '\n'
                            f_out.write(line_new)
                        options = []
                    if section in sections:
                        # Remove the written section from the list
                        sections.remove(section)
                    section = line.strip()[1:-1]
                    if section in sections:
                        # enable write for all entries in that section
                        write = True
                        options = config.options(section)
                        # write the section
                        f_out.write(line)
                    else:
                        # disable writing until next valid section
                        write = False 
                # If write enabled   
                elif write:
                    value = shlex.split(line, True)
                    # If the line is empty or a comment
                    if value == []:
                        f_out.write(line)
                    else:
                        option, value = line.split('=', 1)   
                        try:
                            # split any inline comments
                            value, comment = value.split('#', 1)
                            comment = '#' + comment
                        except ValueError:
                            comment = ''                
                        if option.strip() in options:
                            if config[section][option.strip()] != value.strip():
                                value = value.replace(value, config[section][option.strip()])
                                line = option + '=' + value + comment
                            f_out.write(line)
                            options.remove(option.strip())
    # If any options remain from the preceding section
    if options != []:
        for option in options:
            line = '  ' + option + ' = ' + config[section][option] + '\n'
            f_out.write(line)
    options = []
    # If any new sections are present
    if section in sections:
        sections.remove(section)
    for section in sections:
        f_out.write('\n['+section+']\n')
        options = config.options(section)
        for option in options:
            line = '  ' + option + ' = ' + config[section][option] + '\n'
            f_out.write(line) 