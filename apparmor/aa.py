#1082
#382-430
#480-525
#global variable names corruption
from __future__ import with_statement
import inspect
import logging
import os
import re
import subprocess
import sys
import traceback
import atexit

import apparmor.config
import apparmor.severity
import LibAppArmor

from apparmor.common import (AppArmorException, error, debug, msg, 
                             open_file_read, readkey, valid_path,
                             hasher, open_file_write)

DEBUGGING = False
debug_logger = None

# Setup logging incase of debugging is enabled
if os.getenv('LOGPROF_DEBUG', False):
    DEBUGGING = True
    logprof_debug = os.environ['LOGPROF_DEBUG']
    logging.basicConfig(filename=logprof_debug, level=logging.DEBUG)
    debug_logger = logging.getLogger('logprof')


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
log_dict = dict()
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
    if not path.startswith('/'):
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
        if '/' not in bin_path:
            env_bin = which(bin_path)
            if env_bin:
                full_bin = get_full_path(env_bin)
    if full_bin and os.path.exists(full_bin):
        return full_bin
    return None

def get_profile_filename(profile):
    """Returns the full profile name"""
    if profile.startswith('/'):
        # Remove leading /
        profile = profile[1:]
    else:
        profile = "profile_" + profile
    profile.replace('/', '.')
    full_profilename = profile_dir + '/' + profile
    return full_profilename

def name_to_prof_filename(prof_filename):
    """Returns the profile"""
    if prof_filename.startswith(profile_dir):
        profile = prof_filename.split(profile_dir, 1)[1]
        return (prof_filename, profile)
    else:
        bin_path = find_executable(prof_filename)
        if bin_path:
            prof_filename = get_profile_filename(bin_path)
            if os.path.isfile(prof_filename):
                return (prof_filename, bin_path)
            else:
                return None, None

def complain(path):
    """Sets the profile to complain mode if it exists"""
    prof_filename, name = name_to_prof_filename(path)
    if not prof_filename :
        fatal_error("Can't find %s" % path)
    UI_Info('Setting %s to complain mode.' % name)
    set_profile_flags(prof_filename, 'complain')
    
def enforce(path):
    """Sets the profile to complain mode if it exists"""
    prof_filename, name = name_to_prof_filename(path)
    if not prof_filename :
        fatal_error("Can't find %s" % path)
    UI_Info('Setting %s to enforce moode' % name)
    set_profile_flags(prof_filename, '')
    
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
    ret, ldd_out = get_output([ldd, file])
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

def handle_binfmt(profile, path):
    """Modifies the profile to add the requirements"""
    reqs_processed = dict()
    reqs = get_reqs(path)
    while reqs:
        library = reqs.pop()
        if not reqs_processed.get(library, False):
            reqs.append(get_reqs(library))
            reqs_processed[library] = True
        combined_mode = match_prof_incs_to_path(profile, 'allow', library)
        if combined_mode:
            continue
        library = glob_common(library)
        if not library:
            continue
        try:
            profile['allow']['path'][library]['mode'] |= str_to_mode('mr')
        except TypeError:
            profile['allow']['path'][library]['mode'] = str_to_mode('mr')
        try:
            profile['allow']['path'][library]['audit'] |= 0 
        except TypeError:
            profile['allow']['path'][library]['audit'] = 0
        
def get_inactive_profile(local_profile):
    if extras.get(local_profile, False):
        return {local_profile: extras[local_profile]}
    return dict()

def create_new_profile(localfile):
    local_profile = hasher()
    local_profile[localfile]['flags'] = 'complain'
    local_profile[localfile]['include']['abstractions/base'] = 1 
    #local_profile = {
    #                 localfile: {
    #                           'flags': 'complain',
    #                           'include': {'abstraction/base': 1},
    #                           'allow': {'path': {}}
    #                           }
    #                 }
    if os.path.isfile(localfile):
        hashbang = head(localfile)
        if hashbang.startswith('#!'):
            interpreter = get_full_path(hashbang.lstrip('#!').strip())
            try:
                local_profile[localfile]['allow']['path'][localfile]['mode'] |= str_to_mode('r')
            except TypeError:
                local_profile[localfile]['allow']['path'][localfile]['mode'] = str_to_mode('r')
            try:
                local_profile[localfile]['allow']['path'][localfile]['audit'] |= 0
            except TypeError:
                local_profile[localfile]['allow']['path'][localfile]['audit'] = 0
            try:
                local_profile[localfile]['allow']['path'][interpreter]['mode'] |= str_to_mode('ix')
            except TypeError:
                local_profile[localfile]['allow']['path'][interpreter]['mode'] = str_to_mode('ix')
            try:
                local_profile[localfile]['allow']['path'][interpreter]['audit'] |= 0
            except TypeError:
                local_profile[localfile]['allow']['path'][interpreter]['audit'] = 0
            if 'perl' in interpreter:
                local_profile[localfile]['include']['abstractions/perl'] = 1
            elif 'python' in interpreter:
                local_profile[localfile]['include']['abstractions/python'] = 1
            elif 'ruby' in interpreter:
                local_profile[localfile]['include']['abstractions/ruby'] = 1
            elif '/bin/bash' in interpreter or '/bin/dash' in interpreter or '/bin/sh' in interpreter:
                local_profile[localfile]['include']['abstractions/ruby'] = 1
            handle_binfmt(local_profile[localfile], interpreter)
        else:
            try:
                local_profile[localfile]['allow']['path'][localfile]['mode'] |= str_to_mode('mr')
            except TypeError:
                local_profile[localfile]['allow']['path'][localfile]['mode'] = str_to_mode('mr')
            try:
                local_profile[localfile]['allow']['path'][localfile]['audit'] |= 0
            except TypeError:
                local_profile[localfile]['allow']['path'][localfile] = 0
            handle_binfmt(local_profile[localfile], localfile)
    # Add required hats to the profile if they match the localfile      
    for hatglob in cfg['required_hats'].keys():
        if re.search(hatglob, localfile):
            for hat in sorted(cfg['required_hats'][hatglob].split()):
                local_profile[hat]['flags'] = 'complain'
    
    created.append(localfile)
    if DEBUGGING:
        debug_logger.debug("Profile for %s:\n\t%s" % (localfile, local_profile.__str__()))
    return {localfile: local_profile}
    
def delete_profile(local_prof):
    """Deletes the specified file from the disk and remove it from our list"""
    profile_file = get_profile_filename(local_prof)
    if os.path.isfile(profile_file):
        os.remove(profile_file)
    if aa.get(local_prof, False):
        aa.pop(local_prof)
        
def get_profile(prof_name):
    profile_data = None
    distro = cfg['repository']['distro']
    repo_url = cfg['repository']['url']
    local_profiles = []
    profile_hash = hasher()
    if repo_is_enabled():
        UI_BusyStart('Coonecting to repository.....')
        status_ok, ret = fetch_profiles_by_name(repo_url, distro, prof_name)
        UI_BustStop()
        if status_ok:
            profile_hash = ret
        else:
            UI_Important('WARNING: Error fetching profiles from the repository')
    inactive_profile = get_inactive_profile(prof_name)
    if inactive_profile:
        uname = 'Inactive local profile for %s' % prof_name
        inactive_profile[prof_name][prof_name]['flags'] = 'complain'
        inactive_profile[prof_name][prof_name].pop('filename')
        profile_hash[uname]['username'] = uname
        profile_hash[uname]['profile_type'] = 'INACTIVE_LOCAL'
        profile_hash[uname]['profile'] = serialize_profile(inactive_profile[prof_name], prof_name)
        profile_hash[uname]['profile_data'] = inactive_profile
    # If no profiles in repo and no inactive profiles
    if not profile_hash.keys():
        return None
    options = []
    tmp_list = []
    preferred_present = False
    preferred_user = cfg['repository'].get('preferred_user', 'NOVELL')
    
    for p in profile_hash.keys():
        if profile_hash[p]['username'] == preferred_user:
            preferred_present = True
        else:
            tmp_list.append(profile_hash[p]['username'])
            
    if preferred_present:
        options.append(preferred_user)
    options += tmp_list
    
    q = dict()
    q['headers'] = ['Profile', prof_name]
    q['functions'] = ['CMD_VIEW_PROFILE', 'CMD_USE_PROFILE', 'CMD_CREATE_PROFILE',
                      'CMD_ABORT', 'CMD_FINISHED']
    q['default'] = "CMD_VIEW_PROFILE"
    q['options'] = options
    q['selected'] = 0
    
    ans = ''
    while 'CMD_USE_PROFILE' not in ans and 'CMD_CREATE_PROFILE' not in ans:
        ans, arg = UI_PromptUser(q)
        p = profile_hash[options[arg]]
        q['selected'] = options.index(options[arg])
        if ans == 'CMD_VIEW_PROFILE':
            if UI_mode == 'yast':
                SendDataToYast({
                                'type': 'dialogue-view-profile',
                                'user': options[arg],
                                'profile': p['profile'],
                                'profile_type': p['profile_type']
                                })
                ypath, yarg = GetDataFromYast()
            else:
                pager = get_pager()
                proc = subprocess.Popen(pager, stdin=subprocess.PIPE)
                proc.communicate('Profile submitted by %s:\n\n%s\n\n' % 
                                 (options[arg], p['profile']))
                proc.kill()
        elif ans == 'CMD_USE_PROFILE':
            if p['profile_type'] == 'INACTIVE_LOCAL':
                profile_data = p['profile_data']
                created.append(prof_name)
            else:
                profile_data = parse_repo_profile(prof_name, repo_url, p)
    return profile_data

def activate_repo_profiles(url, profiles, complain):
    read_profiles()
    try:
        for p in profiles:
            pname = p[0]
            profile_data = parse_repo_profile(pname, url, p[1])
            attach_profile_data(aa, profile_data)
            write_profile(pname)
            if complain:
                fname = get_profile_filename(pname)
                set_profile_flags(fname, 'complain')
                UI_Info('Setting %s to complain mode.' % pname)
    except Exception as e:
            sys.stderr.write("Error activating profiles: %s" % e)

def autodep(bin_name, pname=''):
    bin_full = None
    if not bin_name and pname.startswith('/'):
        bin_name = pname
    if not repo_cfg and not cfg['repository'].get('url', False):
        repo_cfg = read_config('repository.conf')
        if not repo_cfg.get('repository', False) or repo_cfg['repository']['enabled'] == 'later':
            UI_ask_to_enable_repo()
    if bin_name:
        bin_full = find_executable(bin_name)
        #if not bin_full:
        #    bin_full = bin_name
        #if not bin_full.startswith('/'):
            #return None
        # Return if exectuable path not found
        if not bin_full:
            return None
    pname = bin_full
    read_inactive_profile()
    profile_data = get_profile(pname)
    # Create a new profile if no existing profile
    if not profile_data:
        profile_data = create_new_profile(pname)
    file = get_profile_filename(pname)
    attach_profile_data(aa, profile_data)
    attach_profile_data(aa_original, profile_data)
    if os.path.isfile(profile_dir + '/tunables/global'):
        if not filelist.get(file, False):
            filelist.file = hasher()
        filelist[file][include]['tunables/global'] = True
    write_profile_ui_feedback(pname)
    
def set_profile_flags(prof_filename, newflags):
    """Reads the old profile file and updates the flags accordingly"""
    regex_bin_flag = re.compile('^(\s*)(("??\/.+?"??)|(profile\s+("??.+?"??)))\s+(flags=\(.+\)\s+)*\{\s*$/')
    regex_hat_flag = re.compile('^(\s*\^\S+)\s+(flags=\(.+\)\s+)*\{\s*$')
    if os.path.isfile(prof_filename):
        with open_file_read(prof_filename) as f_in:
            with open_file_write(prof_filename + '.new') as f_out:
                for line in f_in:
                    match = regex_bin_flag.search(line)
                    if match:
                        space, binary, flags = match.groups()
                        if newflags:
                            line = '%s%s flags=(%s) {\n' % (space, binary, newflags)
                        else:
                            line = '%s%s {\n' % (space, binary)
                    else:
                        match = regex_hat_flag.search(line)
                        if match:
                            hat, flags = match.groups()
                            if newflags:
                                line = '%s flags=(%s) {\n' % (hat, newflags)
                            else:
                                line = '%s {\n' % hat
                    f_out.write(line)
        os.rename(prof_filename+'.new', prof_filename)

def profile_exists(program):
    """Returns True if profile exists, False otherwise"""
    # Check cache of profiles
    if existing_profiles.get(program, False):
        return True
    # Check the disk for profile
    prof_path = get_profile_filename(program)
    if os.path.isfile(prof_path):
        # Add to cache of profile
        existing_profiles[program] = True
        return True
    return False
