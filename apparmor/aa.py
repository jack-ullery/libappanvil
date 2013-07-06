#711
#382-430
#480-525
#global variable names corruption
from __future__ import with_statement
import inspect
import os
import re
import subprocess
import sys
import traceback

DEBUGGING = False
debug_logger = None

# Setup logging incase of debugging is enabled
if os.getenv('LOGPROF_DEBUG', False):
    import logging, atexit
    DEBUGGING = True
    logprof_debug = os.environ['LOGPROF_DEBUG']
    logging.basicConfig(filename=logprof_debug, level=logging.DEBUG)
    debug_logger = logging.getLogger('logprof')

import apparmor.config
import apparmor.severity
import LibAppArmor

from apparmor.common import AppArmorException, error, debug, msg, open_file_read, readkey, valid_path



CONFDIR = '/etc/apparmor'
running_under_genprof = False
unimplemented_warning = False
# The operating mode: yast or text, text by default
UI_mode = 'text'
# The database for severity
sev_db = None
# The file to read log messages from
### Was our
filename = None

cfg = None
repo_cfg = None

parser = None
ldd = None
logger = None
profile_dir = None
extra_profile_dir = None
### end our
# To keep track of previously included profile fragments
include = dict()

existing_profiles = dict()

seen_events = 0     # was our
# To store the globs entered by users so they can be provided again
user_globs = []

## Variables used under logprof
### Were our
t = dict()   
transitions = dict() 
aa = dict()  # Profiles originally in sd, replace by aa
original_aa =  dict()
extras = dict()  # Inactive profiles from extras
### end our
log = []
pid = None

seen = dir()
profile_changes = dict()
prelog = dict()
log = dict()
changed = dict()
created = []
helpers = dict() # Preserve this between passes # was our
### logprof ends

filelist = dict()    # File level variables and stuff in config files

AA_MAY_EXEC = 1
AA_MAY_WRITE = 2
AA_MAY_READ = 4
AA_MAY_APPEND = 8
AA_MAY_LINK = 16
AA_MAY_LOCK = 32
AA_EXEC_MMAP = 64
AA_EXEC_UNSAFE = 128
AA_EXEC_INHERIT = 256
AA_EXEC_UNCONFINED = 512
AA_EXEC_PROFILE = 1024
AA_EXEC_CHILD = 2048
AA_EXEC_NT = 4096
AA_LINK_SUBSET = 8192
AA_OTHER_SHIFT = 14
AA_USER_MASK = 16384 - 1

AA_EXEC_TYPE = (AA_MAY_EXEC | AA_EXEC_UNSAFE | AA_EXEC_INHERIT |
                AA_EXEC_UNCONFINED | AA_EXEC_PROFILE | AA_EXEC_CHILD | AA_EXEC_NT)

ALL_AA_EXEC_TYPE = AA_EXEC_TYPE # The same value

# Modes and their values
MODE_HASH = {'x': AA_MAY_EXEC, 'X': AA_MAY_EXEC, 
             'w': AA_MAY_WRITE, 'W': AA_MAY_WRITE,
             'r': AA_MAY_READ, 'R': AA_MAY_READ,
             'a': AA_MAY_APPEND, 'A': AA_MAY_APPEND,
             'l': AA_MAY_LINK, 'L': AA_MAY_LINK,
             'k': AA_MAY_LOCK, 'K': AA_MAY_LOCK,
             'm': AA_EXEC_MMAP, 'M': AA_EXEC_MMAP,
             'i': AA_EXEC_INHERIT, 'I': AA_EXEC_INHERIT,
             'u': AA_EXEC_UNCONFINED + AA_EXEC_UNSAFE,  # Unconfined + Unsafe
              'U': AA_EXEC_UNCONFINED,
              'p': AA_EXEC_PROFILE + AA_EXEC_UNSAFE,    # Profile + unsafe
              'P': AA_EXEC_PROFILE,
              'c': AA_EXEC_CHILD + AA_EXEC_UNSAFE,  # Child + Unsafe
              'C': AA_EXEC_CHILD,
              'n': AA_EXEC_NT + AA_EXEC_UNSAFE,
              'N': AA_EXEC_NT
              }

# Used by netdomain to identify the operation types
OPERATION_TYPES = {
                   # New socket names
                   'create': 'net',
                   'post_create': 'net',
                   'bind': 'net',
                   'connect': 'net',
                   'listen': 'net',
                   'accept': 'net',
                   'sendmsg': 'net',
                   'recvmsg': 'net',
                   'getsockname': 'net',
                   'getpeername': 'net',
                   'getsockopt': 'net',
                   'setsockopt': 'net',
                   'sock_shutdown': 'net'
                   }

ARROWS = {'A': 'UP', 'B': 'DOWN', 'C': 'RIGHT', 'D': 'LEFT'}

def on_exit():
    """Shutdowns the logger and records exit if debugging enabled"""
    if DEBUGGING:
        debug_logger.debug('Exiting..')
        logging.shutdown()
        
# Register the on_exit method with atexit
atexit.register(on_exit)

def opt_type(operation):
    """Returns the operation type if known, unkown otherwise"""
    operation_type = OPERATION_TYPES.get(operation, 'unknown')
    return operation_type

def getkey():
    key = readkey()
    if key == '\x1B':
        key = readkey()
        if key == '[':
            key = readkey()
            if(ARROWS.get(key, False)):
                key = ARROWS[key]
    return key

def check_for_LD_XXX(file):
    """Returns True if specified program contains references to LD_PRELOAD or 
    LD_LIBRARY_PATH to give the PX/UX code better suggestions"""
    found = False
    if not os.path.isfile(file):
        return False
    size = os.stat(file).st_size
    # Limit to checking files under 10k for the sake of speed
    if size >10000:
        return False
    with open_file_read(file) as f_in:
        for line in f_in:
            if 'LD_PRELOAD' in line or 'LD_LIBRARY_PATH' in line:
                found = True
    return found

def fatal_error(message):
    if DEBUGGING:
        # Get the traceback to the message
        tb_stack = traceback.format_list(traceback.extract_stack())
        tb_stack = ''.join(tb_stack)
        # Append the traceback to message
        message = message + '\n' + tb_stack
        debug_logger.error(message)
    caller = inspect.stack()[1][3]
    
    # If caller is SendDataToYast or GetDatFromYast simply exit
    sys.exit(1)
    
    # Else tell user what happened
    UI_Important(message)
    shutdown_yast()
    sys.exit(1)

def setup_yast():
    # To-Do
    pass   

def shutdown_yast():
    # To-Do
    pass
     
def check_for_apparmor():
    """Finds and returns the mointpoint for apparmor None otherwise"""
    filesystem = '/proc/filesystems'
    mounts = '/proc/mounts'
    support_securityfs = False
    aa_mountpoint = None
    regex_securityfs = re.compile('^\S+\s+(\S+)\s+securityfs\s')
    if valid_path(filesystem):
        with open_file_read(filesystem) as f_in:
            for line in f_in:
                if 'securityfs' in line:
                    support_securityfs = True
    if valid_path(mounts):
        with open_file_read(mounts) as f_in:
            for line in f_in:
                if support_securityfs:
                    match = regex_securityfs.search(line)
                    if match:
                        mountpoint = match.groups()[0] + '/apparmor'
                        if valid_path(mountpoint):
                            aa_mountpoint = mountpoint    
    # Check if apparmor is actually mounted there
    if not valid_path(aa_mountpoint + '/profiles'):
        aa_mountpoint = None
    return aa_mountpoint

def which(file):
    """Returns the executable fullpath for the file, None otherwise"""
    env_dirs = os.getenv('PATH').split(':')
    for env_dir in env_dirs:
        env_path = env_dir + '/' + file
        # Test if the path is executable or not
        if os.access(env_path, os.X_OK):
            return env_path
    return None

def convert_regexp(regexp):
    ## To Do
    #regex_escape = re.compile('(?<!\\)(\.|\+|\$)')
    #regexp = regex_escape.sub('\\')
    new_reg = re.sub(r'(?<!\\)(\.|\+|\$)',r'\\\1',regexp)
    
    new_reg = new_reg.replace('?', '[^/\000]')
    dup='_SGDHBGFHFGFJFGBVHGFFGHF_MFMFH_'
    new_reg = new_reg.replace('**', dup)
    #de_dup=r'((?<=/)[^\000]*|(?<!/)[^\000]+)'
    de_dup=r'((?<=/).*|(?<!/).+)'
    #new_reg = new_reg.replace('*', r'((?<=/)[^/\000]*|(?<!/)[^/\000]+)')
    new_reg = new_reg.replace('*', r'((?<=/)[^/]*|(?<!/)[^/]+)')
    new_reg = new_reg.replace(dup, de_dup)
    return new_reg
    
    
def get_full_path(original_path):
    """Return the full path after resolving any symlinks"""
    path = original_path
    link_count = 0
    if not '/' in path:
        path = os.getcwd() + '/' + path
    while os.path.islink(path):
        link_count += 1
        if link_count > 64:
            fatal_error("Followed too many links while resolving %s" % (original_path))
        direc, file = os.path.split(path)
        link = os.readlink(path)
        # If the link an absolute path
        if link.startswith('/'):
            path = link
        else:
            # Link is relative path
            path = direc + '/' + link
    return os.path.realpath(path)

def find_executable(bin_path):
    """Returns the full executable path for the binary given, None otherwise"""
    full_bin = None
    if os.path.exists(bin_path):
        full_bin = get_full_path(bin_path)
    else:
        if '/' not in bin:
            env_bin = which(bin)
            if env_bin:
                full_bin = get_full_path(env_bin)
    if full_bin and os.path.exists(full_bin):
        return full_bin
    return None

def get_profile_filename(profile):
    """Returns the full profile name"""
    filename = profile
    if filename.startswith('/'):
        # Remove leading /
        filename = filename[1:]
    else:
        filename = "profile_" + filename
    filename.replace('/', '.')
    full_profilename = profile_dir + '/' + filename
    return full_profilename

def name_to_prof_filename(filename):
    """Returns the profile"""
    if bin.startswith(profile_dir):
        profile = filename.split(profile_dir, 1)[1]
        return (filename, profile)
    else:
        bin_path = find_executable(filename)
        if bin_path:
            filename = get_profile_filename(bin_path)
            if os.path.isfile(filename):
                return (filename, bin_path)
            else:
                return None, None

def complain(path):
    """Sets the profile to complain mode if it exists"""
    filename, name = name_to_prof_filename(path)
    if not filename :
        fatal_error("Can't find %s" % path)
    UI_Info('Setting %s to complain mode.' % name)
    set_profile_flags(filename, 'complain')
    
def enforce(path):
    """Sets the profile to complain mode if it exists"""
    filename, name = name_to_prof_filename(path)
    if not filename :
        fatal_error("Can't find %s" % path)
    UI_Info('Setting %s to enforce moode' % name)
    set_profile_flags(filename, '')
    
def head(file):
    """Returns the first/head line of the file"""
    first = ''
    if os.path.isfile(file):
        with open_file_read(file) as f_in:
            first = f_in.readline().rstrip()
    return first

def get_output(params):
    """Returns the return code output by running the program with the args given in the list"""
    program = params[0]
    args = params[1:]
    ret = -1
    output = []
    # program is executable
    if os.access(program, os.X_OK):
        try:
            # Get the output of the program
            output = subprocess.check_output(params)
        except OSError as e:
            raise  AppArmorException("Unable to fork: %s\n\t%s" %(program, str(e)))
            # If exit-codes besides 0
        except subprocess.CalledProcessError as e:
            output = e.output
            output = output.decode('utf-8').split('\n')
            ret = e.returncode
        else:
            ret = 0
            output = output.decode('utf-8').split('\n')
    # Remove the extra empty string caused due to \n if present
    if len(output) > 1:
        output.pop()             
    return (ret, output)   
        
def get_reqs(file):
    """Returns a list of paths from ldd output"""
    pattern1 = re.compile('^\s*\S+ => (\/\S+)')
    pattern2 = re.compile('^\s*(\/\S+)')
    reqs = []
    ret, ldd_out = get_output(ldd, file)
    if ret == 0:
        for line in ldd_out:
            if 'not a dynamic executable' in line:
                break
            if 'cannot read header' in line:
                break
            if 'statically linked' in line:
                break
            match = pattern1.search(line)
            if match:
                reqs.append(match.groups()[0])
            else:
                match = pattern2.search(line)
                if match:
                    reqs.append(match.groups()[0])
    return reqs

def handle_binfmt(profile, fqdbin):
    reqs = dict()
    