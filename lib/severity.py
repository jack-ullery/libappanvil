import os
import re

class Severity:
    def __init__(self, dbname=None, default_rank=10):
        """Initialises the class object"""
        self.severity = dict()
        self.severity['DATABASENAME'] = dbname
        self.severity['CAPABILITIES'] = {}
        self.severity['FILES'] = {}
        self.severity['REGEXPS'] = {}
        self.severity['DEFAULT_RANK'] = default_rank
        # For variable expansions from /etc/apparmor.d
        self.severity['VARIABLES'] = dict()
        # Recursively visits all the profiles to identify all the variable expansions and stores them
        for root, dirs, files in os.walk('/etc/apparmor.d'):
            for file in files:
                for line in open(os.path.join(root, file), 'r'):
                    line.strip()
                    # Expected format is @{Variable} = value1 value2 ..
                    if line.startswith('@') and '=' in line:
                        line = line.strip()
                        line = line.split('=')
                        self.severity['VARIABLES'][line[0]] = [i.strip('"') for i in line[1].split()] 
        if not dbname:
            return None
        try:
            database = open(dbname, 'r')
        except IOError:
            raise IOError("Could not open severity database %s"%dbname)
        for line in database:
            line = line.strip() # or only rstrip and lstrip?
            if line == '' or line.startswith('#') :
                continue
            if line.startswith('/'):
                try:
                    path, read, write, execute = line.split()
                    read, write, execute = int(read), int(write), int(execute)
                except ValueError:
                    raise ValueError("Insufficient values for permissions in line: %s\nin File: %s"%(line, dbname))
                else:
                    if read not in range(0,11) or write not in range(0,11) or execute not in range(0,11):
                        raise ValueError("Inappropriate values for permissions in line: %s\nin File: %s"%(line, dbname))
                    path = path.lstrip('/')
                    if '*' not in path:
                        self.severity['FILES'][path] = {'r': read, 'w': write, 'x': execute}
                    else:
                        ptr = self.severity['REGEXPS']
                        pieces = path.split('/')
                        for index, piece in enumerate(pieces):
                            if '*' in piece:
                                path = '/'.join(pieces[index:])
                                regexp = self.convert_regexp(path)
                                ptr[regexp] = {'AA_RANK': {'r': read, 'w': write, 'x': execute}}
                                break
                            else:
                                ptr[piece] = ptr.get(piece, {})
                                ptr = ptr[piece]
            elif line.startswith('CAP_'):
                try:
                    resource, severity = line.split()
                    severity = int(severity)
                except ValueError:
                    raise ValueError("No severity value present in line: %s\nin File: %s"%(line, dbname))
                else:
                    if severity not in range(0,11):
                        raise ValueError("Inappropriate severity value present in line: %s\nin File: %s"%(line, dbname))
                    self.severity['CAPABILITIES'][resource] = severity
            else:
                raise ValueError("Unexpected database line: %s \nin File: %s"%(line,dbname))   
        database.close()
        
    def convert_regexp(self, path):
        """Returns the regex form of the path"""
        pattern_or = re.compile('{.*\,.*}')    # The regex pattern for {a,b}
        internal_glob = '__KJHDKVZH_AAPROF_INTERNAL_GLOB_SVCUZDGZID__'
        regex = path
        for character in ['.', '+', '[', ']']:    # Escape the regex symbols
            regex = regex.replace(character, "\%s"%character)
        # Convert the ** to regex
        regex = regex.replace('**', '.'+internal_glob)
        # Convert the * to regex
        regex = regex.replace('*', '[^/]'+internal_glob)
        # Convert {a,b} to (a|b) form
        if pattern_or.match(regex):
            for character, replacement in zip('{},', '()|'):
                regex = regex.replace(character, replacement)
        # Restore the * in the final regex
        regex = regex.replace(internal_glob, '*')
        return regex
    
    def handle_capability(self, resource):
        """Returns the severity of for the capability resource, default value if no match"""
        if resource in self.severity['CAPABILITIES'].keys():
            return self.severity['CAPABILITIES'][resource]
        # raise ValueError("unexpected capability rank input: %s"%resource)
        return self.severity['DEFAULT_RANK']
        
    
    def check_subtree(self, tree, mode, sev, segments):
        """Returns the max severity from the regex tree"""
        if len(segments) == 0:
            first = ''
        else:
            first = segments[0]
        rest = segments[1:]
        path = '/'.join([first]+rest)
        # Check if we have a matching directory tree to descend into
        if tree.get(first, False):
            sev = self.check_subtree(tree[first], mode, sev, rest)
        # If severity still not found, match against globs
        if sev == None:
            # Match against all globs at this directory level
            for chunk in tree.keys():
                if '*' in chunk:
                    # Match rest of the path
                    if re.search("^"+chunk, path):
                        # Find max rank 
                        if "AA_RANK" in tree[chunk].keys():
                            for m in mode:
                                if sev == None or tree[chunk]["AA_RANK"].get(m, -1) > sev:
                                    sev = tree[chunk]["AA_RANK"].get(m, None)
        return sev
            
    def handle_file(self, resource, mode):
        """Returns the severity for the file, default value if no match found"""
        resource = resource[1:]    # remove initial / from path
        pieces = resource.split('/')    # break path into directory level chunks
        sev = None
        # Check for an exact match in the db
        if resource in self.severity['FILES'].keys():
            # Find max value among the given modes
            for m in mode:
                if sev == None or self.severity['FILES'][resource].get(m, -1) > sev:
                    sev = self.severity['FILES'][resource].get(m, None)
        else:
            # Search regex tree for matching glob
            sev = self.check_subtree(self.severity['REGEXPS'], mode, sev, pieces)
        if sev == None:
            # Return default rank if severity cannot be found
            return self.severity['DEFAULT_RANK']
        else:
            return sev
        
    def rank(self, resource, mode=None):
        """Returns the rank for the resource file/capability"""
        if '@' in resource:    # path contains variable
            return self.handle_variable_rank(resource, mode)
        elif resource[0] == '/':    # file resource
            return self.handle_file(resource, mode)
        elif resource[0:4] == 'CAP_':    # capability resource
            return self.handle_capability(resource)
        else:
            raise ValueError("Unexpected rank input: %s"%resource)
        
    def handle_variable_rank(self, resource, mode):
        """Returns the max possible rank for file resources containing variables"""
        regex_variable = re.compile('@{([^{.]*)}')
        rank = None
        if '@' in resource:
            variable = regex_variable.search(resource).groups()[0]
            variable = '@{'+variable+'}'
            #variables = regex_variable.findall(resource)
            for replacement in self.severity['VARIABLES'][variable]:
                resource_replaced = self.variable_replace(variable, replacement, resource)
                rank_new = self.handle_variable_rank(resource_replaced, mode)
                #rank_new = self.handle_variable_rank(resource.replace('@{'+variable+'}', replacement), mode)     
                if rank == None or rank_new > rank:
                    rank = rank_new
            return rank
        else:
            #print(resource)
            #print(self.handle_file(resource, mode))
            return self.handle_file(resource, mode)
            
    def variable_replace(self, variable, replacement, resource):
        """Returns the expanded path for the passed variable"""
        leading = False
        trailing = False
        # Check for leading or trailing / that may need to be collapsed
        if resource.find("/"+variable) != -1 and resource.find("//"+variable) == -1:
            leading = True
        if resource.find(variable+"/") != -1 and resource.find(variable+"//") == -1:
            trailing = True
        if replacement[0] == '/' and replacement[0:2] != '//' and leading:
            replacement = replacement[1:]
        if replacement[-1] == '/' and replacement[-1:-2:-1] !='//' and trailing:
            replacement = replacement[:-1]
        return resource.replace(variable, replacement)