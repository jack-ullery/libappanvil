def write_header(prof_data, depth, name, embedded_hat, write_flags):
    pre = '  ' * depth
    data = []
    name = quote_if_needed(name)
    
    if (not embedded_hat and re.search('^[^/]|^"[^/]', name)) or (embedded_hat and re.search('^[^^]' ,name)):
        name = 'profile %s' % name
    
    if write_flags and prof_data['flags']:
        data.append('%s%s flags=(%s) {' % (pre, name, prof_data['flags']))
    else:
        data.append('%s%s {' % (pre, name))
    
    return data

def write_rules(prof_data, depth):
    data = write_alias(prof_data, depth)
    data += write_list_vars(prof_data, depth)
    data += write_includes(prof_data, depth)
    data += write_rlimits(prof_data, depth)
    data += write_capabilities(prof_data, depth)
    data += write_netdomain(prof_data, depth)
    data += write_links(prof_data, depth)
    data += write_paths(prof_data, depth)
    data += write_change_profile(prof_data, depth)
    
    return data

def write_piece(profile_data, depth, name, nhat, write_flags):
    pre = '  ' * depth
    data = []
    wname = None
    inhat = False
    if name == nhat:
        wname = name
    else:
        wname = name + '//' + nhat
        name = nhat
        inhat = True
    data += ['begin header']
    data += write_header(profile_data[name], depth, wname, False, write_flags)
    data +=['end header']
    data += write_rules(profile_data[name], depth+1)
    
    pre2 = '  ' * (depth+1)
    # External hat declarations
    for hat in list(filter(lambda x: x != name, sorted(profile_data.keys()))):
        if profile_data[hat].get('declared', False):
            data.append('%s^%s,' %(pre2, hat))
    
    if not inhat:
        # Embedded hats
        for hat in list(filter(lambda x: x != name, sorted(profile_data.keys()))):
            if not profile_data[hat]['external'] and not profile_data[hat]['declared']:
                data.append('')
                if profile_data[hat]['profile']:
                    data += list(map(str, write_header(profile_data[hat], depth+1, hat, True, write_flags)))
                else:
                    data += list(map(str, write_header(profile_data[hat], depth+1, '^'+hat, True, write_flags)))
                
                data += list(map(str, write_rules(profile_data[hat], depth+2)))
                
                data.append('%s}' %pre2)
        
        data.append('%s}' %pre)
        
        # External hats
        for hat in list(filter(lambda x: x != name, sorted(profile_data.keys()))):
            if name == nhat and profile_data[hat].get('external', False):
                data.append('')
                data += list(map(lambda x: '  %s' %x, write_piece(profile_data, depth-1, name, nhat, write_flags)))
                data.append('  }')
        
    return data
            
    
def serialize_profile(profile_data, name, options):
    string = ''
    include_metadata = False
    include_flags = True
    data= []
    
    if options:# and type(options) == dict:
        if options.get('METADATA', False):
            include_metadata = True
        if options.get('NO_FLAGS', False):
            include_flags = False
    
    if include_metadata:
        string = '# Last Modified: %s\n' %time.time()
        
        if (profile_data[name].get('repo', False) and profile_data[name]['repo']['url']
            and profile_data[name]['repo']['user'] and profile_data[name]['repo']['id']):
            repo = profile_data[name]['repo']
            string += '# REPOSITORY: %s %s %s\n' %(repo['url'], repo['user'], repo['id'])
        elif profile_data[name]['repo']['neversubmit']:
            string += '# REPOSITORY: NEVERSUBMIT\n'
    
    if profile_data[name].get('initial_comment', False):
        comment = profile_data[name]['initial_comment']
        comment.replace('\\n', '\n')
        string += comment + '\n'
    
    prof_filename = get_profile_filename(name)
    if filelist.get(prof_filename, False):
        data += write_alias(filelist[prof_filename], 0)
        data += write_list_vars(filelist[prof_filename], 0)
        data += write_includes(filelist[prof_filename], 0)
    
    data += write_piece(profile_data, 0, name, name, include_flags)
    
    string += '\n'.join(data)
    
    return string+'\n'
