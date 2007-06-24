# This file was created automatically by SWIG 1.3.29.
# Don't modify this file, modify the SWIG interface instead.
# This file is compatible with both classic and new-style classes.

import _AppArmorLogRecordParser
import new
new_instancemethod = new.instancemethod
def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "thisown"): return self.this.own(value)
    if (name == "this"):
        if type(value).__name__ == 'PySwigObject':
            self.__dict__[name] = value
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static) or hasattr(self,name):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    if (name == "thisown"): return self.this.own()
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError,name

def _swig_repr(self):
    try: strthis = "proxy of " + self.this.__repr__()
    except: strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)

import types
try:
    _object = types.ObjectType
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0
del types


AA_RECORD_EXEC_MMAP = _AppArmorLogRecordParser.AA_RECORD_EXEC_MMAP
AA_RECORD_READ = _AppArmorLogRecordParser.AA_RECORD_READ
AA_RECORD_WRITE = _AppArmorLogRecordParser.AA_RECORD_WRITE
AA_RECORD_EXEC = _AppArmorLogRecordParser.AA_RECORD_EXEC
AA_RECORD_LINK = _AppArmorLogRecordParser.AA_RECORD_LINK
AA_RECORD_SYNTAX_V1 = _AppArmorLogRecordParser.AA_RECORD_SYNTAX_V1
AA_RECORD_SYNTAX_V2 = _AppArmorLogRecordParser.AA_RECORD_SYNTAX_V2
AA_RECORD_SYNTAX_UNKNOWN = _AppArmorLogRecordParser.AA_RECORD_SYNTAX_UNKNOWN
AA_RECORD_INVALID = _AppArmorLogRecordParser.AA_RECORD_INVALID
AA_RECORD_ERROR = _AppArmorLogRecordParser.AA_RECORD_ERROR
AA_RECORD_AUDIT = _AppArmorLogRecordParser.AA_RECORD_AUDIT
AA_RECORD_ALLOWED = _AppArmorLogRecordParser.AA_RECORD_ALLOWED
AA_RECORD_DENIED = _AppArmorLogRecordParser.AA_RECORD_DENIED
AA_RECORD_HINT = _AppArmorLogRecordParser.AA_RECORD_HINT
AA_RECORD_STATUS = _AppArmorLogRecordParser.AA_RECORD_STATUS
class aa_log_record(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, aa_log_record, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, aa_log_record, name)
    __repr__ = _swig_repr
    __swig_setmethods__["version"] = _AppArmorLogRecordParser.aa_log_record_version_set
    __swig_getmethods__["version"] = _AppArmorLogRecordParser.aa_log_record_version_get
    if _newclass:version = property(_AppArmorLogRecordParser.aa_log_record_version_get, _AppArmorLogRecordParser.aa_log_record_version_set)
    __swig_setmethods__["event"] = _AppArmorLogRecordParser.aa_log_record_event_set
    __swig_getmethods__["event"] = _AppArmorLogRecordParser.aa_log_record_event_get
    if _newclass:event = property(_AppArmorLogRecordParser.aa_log_record_event_get, _AppArmorLogRecordParser.aa_log_record_event_set)
    __swig_setmethods__["pid"] = _AppArmorLogRecordParser.aa_log_record_pid_set
    __swig_getmethods__["pid"] = _AppArmorLogRecordParser.aa_log_record_pid_get
    if _newclass:pid = property(_AppArmorLogRecordParser.aa_log_record_pid_get, _AppArmorLogRecordParser.aa_log_record_pid_set)
    __swig_setmethods__["task"] = _AppArmorLogRecordParser.aa_log_record_task_set
    __swig_getmethods__["task"] = _AppArmorLogRecordParser.aa_log_record_task_get
    if _newclass:task = property(_AppArmorLogRecordParser.aa_log_record_task_get, _AppArmorLogRecordParser.aa_log_record_task_set)
    __swig_setmethods__["bitmask"] = _AppArmorLogRecordParser.aa_log_record_bitmask_set
    __swig_getmethods__["bitmask"] = _AppArmorLogRecordParser.aa_log_record_bitmask_get
    if _newclass:bitmask = property(_AppArmorLogRecordParser.aa_log_record_bitmask_get, _AppArmorLogRecordParser.aa_log_record_bitmask_set)
    __swig_setmethods__["operation"] = _AppArmorLogRecordParser.aa_log_record_operation_set
    __swig_getmethods__["operation"] = _AppArmorLogRecordParser.aa_log_record_operation_get
    if _newclass:operation = property(_AppArmorLogRecordParser.aa_log_record_operation_get, _AppArmorLogRecordParser.aa_log_record_operation_set)
    __swig_setmethods__["denied_mask"] = _AppArmorLogRecordParser.aa_log_record_denied_mask_set
    __swig_getmethods__["denied_mask"] = _AppArmorLogRecordParser.aa_log_record_denied_mask_get
    if _newclass:denied_mask = property(_AppArmorLogRecordParser.aa_log_record_denied_mask_get, _AppArmorLogRecordParser.aa_log_record_denied_mask_set)
    __swig_setmethods__["requested_mask"] = _AppArmorLogRecordParser.aa_log_record_requested_mask_set
    __swig_getmethods__["requested_mask"] = _AppArmorLogRecordParser.aa_log_record_requested_mask_get
    if _newclass:requested_mask = property(_AppArmorLogRecordParser.aa_log_record_requested_mask_get, _AppArmorLogRecordParser.aa_log_record_requested_mask_set)
    __swig_setmethods__["profile"] = _AppArmorLogRecordParser.aa_log_record_profile_set
    __swig_getmethods__["profile"] = _AppArmorLogRecordParser.aa_log_record_profile_get
    if _newclass:profile = property(_AppArmorLogRecordParser.aa_log_record_profile_get, _AppArmorLogRecordParser.aa_log_record_profile_set)
    __swig_setmethods__["name"] = _AppArmorLogRecordParser.aa_log_record_name_set
    __swig_getmethods__["name"] = _AppArmorLogRecordParser.aa_log_record_name_get
    if _newclass:name = property(_AppArmorLogRecordParser.aa_log_record_name_get, _AppArmorLogRecordParser.aa_log_record_name_set)
    __swig_setmethods__["name2"] = _AppArmorLogRecordParser.aa_log_record_name2_set
    __swig_getmethods__["name2"] = _AppArmorLogRecordParser.aa_log_record_name2_get
    if _newclass:name2 = property(_AppArmorLogRecordParser.aa_log_record_name2_get, _AppArmorLogRecordParser.aa_log_record_name2_set)
    __swig_setmethods__["attribute"] = _AppArmorLogRecordParser.aa_log_record_attribute_set
    __swig_getmethods__["attribute"] = _AppArmorLogRecordParser.aa_log_record_attribute_get
    if _newclass:attribute = property(_AppArmorLogRecordParser.aa_log_record_attribute_get, _AppArmorLogRecordParser.aa_log_record_attribute_set)
    __swig_setmethods__["parent"] = _AppArmorLogRecordParser.aa_log_record_parent_set
    __swig_getmethods__["parent"] = _AppArmorLogRecordParser.aa_log_record_parent_get
    if _newclass:parent = property(_AppArmorLogRecordParser.aa_log_record_parent_get, _AppArmorLogRecordParser.aa_log_record_parent_set)
    __swig_setmethods__["magic_token"] = _AppArmorLogRecordParser.aa_log_record_magic_token_set
    __swig_getmethods__["magic_token"] = _AppArmorLogRecordParser.aa_log_record_magic_token_get
    if _newclass:magic_token = property(_AppArmorLogRecordParser.aa_log_record_magic_token_get, _AppArmorLogRecordParser.aa_log_record_magic_token_set)
    __swig_setmethods__["info"] = _AppArmorLogRecordParser.aa_log_record_info_set
    __swig_getmethods__["info"] = _AppArmorLogRecordParser.aa_log_record_info_get
    if _newclass:info = property(_AppArmorLogRecordParser.aa_log_record_info_get, _AppArmorLogRecordParser.aa_log_record_info_set)
    __swig_setmethods__["active_hat"] = _AppArmorLogRecordParser.aa_log_record_active_hat_set
    __swig_getmethods__["active_hat"] = _AppArmorLogRecordParser.aa_log_record_active_hat_get
    if _newclass:active_hat = property(_AppArmorLogRecordParser.aa_log_record_active_hat_get, _AppArmorLogRecordParser.aa_log_record_active_hat_set)
    def __init__(self, *args): 
        this = _AppArmorLogRecordParser.new_aa_log_record(*args)
        try: self.this.append(this)
        except: self.this = this
    __swig_destroy__ = _AppArmorLogRecordParser.delete_aa_log_record
    __del__ = lambda self : None;
aa_log_record_swigregister = _AppArmorLogRecordParser.aa_log_record_swigregister
aa_log_record_swigregister(aa_log_record)

parse_record = _AppArmorLogRecordParser.parse_record
free_record = _AppArmorLogRecordParser.free_record


