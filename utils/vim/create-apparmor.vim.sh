#!/bin/bash

# not-too-dangerous capabilities
sdKapKey="chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_chroot sys_ptrace sys_pacct sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease"

# dangerous capabilities
sdKapKeyDanger="audit_control audit_write mac_override mac_admin set_fcap sys_admin sys_module sys_rawio"

sdNetworkProto="inet|ax25|ipx|appletalk|netrom|bridge|atmpvc|x25|inet6|rose|netbeui|security|key|packet|ash|econet|atmsvc|sna|irda|pppox|wanpipe|bluetooth"

sdNetworkType='\s+tcp|\s+udp|\s+icmp'

sdFlags="complain|audit|attach_disconnect|no_attach_disconnected|chroot_attach|chroot_no_attach|chroot_relative|namespace_relative"
# TODO: does a "debug" flag exist? Listed in apparmor.vim.in sdFlagKey, but not in sdFlags...
# -> currently (2011-01-11) not, but might come back

sdKapKeyRegex="$(echo "$sdKapKey $sdKapKeyDanger" | sed 's/ /|/g')"

sdFlagsRegex="($sdFlags)"

#	'@@FILE@@'            '\v^\s*((owner\s+)|(audit\s+)|(deny\s+))*(\/|\@\{\S*\})\S*\s+'   \
replace                                                                                    \
	'@@FILE@@'            '\v^\s*(audit\s+)?(deny\s+)?(owner\s+)?(\/|\@\{\S*\})\S*\s+'     \
    '@@auditdenyowner@@'  '(audit\s+)?(deny\s+)?(owner\s+)?'                               \
    '@@auditdeny@@'       '(audit\s+)?(deny\s+)?'                                          \
	'@@FILENAME@@'        '(\/|\@\{\S*\})\S*'                                              \
	'@@EOL@@'             '\s*,(\s*$|(\s*#.*$)\@=)'                                        \
	'@@TRANSITION@@'      '(\s+-\>\s+\S+)?'                                                \
	'@@sdKapKey@@'        "$sdKapKey"                                                      \
	'@@sdKapKeyDanger@@'  "$sdKapKeyDanger"                                                \
	'@@sdKapKeyRegex@@'   "$sdKapKeyRegex"                                                 \
	'@@sdNetworkProto@@'  "$sdNetworkProto"                                                \
	'@@sdNetworkType@@'   "$sdNetworkType"                                                 \
	'@@flags@@'           "((flags\s*\=\s*)?\(\s*$sdFlagsRegex(\s*,\s*$sdFlagsRegex)*\s*\)\s+)"         \
	                                                                                       \
< apparmor.vim.in                                                                          \
> apparmor.vim


# @@FILE@@: Start of a file rule (whitespace_+_, owner etc. flag_?_, filename pattern, whitespace_+_)
# @@FILENAME@@: Just a filename (taken from @@FILE@@)
# @@EOL@@: End of a line (whitespace_?_, comma, whitespace_?_ comment.*)


# I had to learn that vim has a restriction on the number of (...) I may use in
# a RegEx (up to 9 are allowed), and therefore had to change the RegEx that
# matches tcp/udp/icmp from "(\s+(tcp|udp|icmp))?" to
# "(\s+tcp|\s+udp|\s+icmp)?". *argh*
# (sdNetworkProto could be changed the same way if needed)


# TODO: permissions first
# valid rules:
# owner rw /foo,
# owner /foo rw,

# INVALID rules
# rw owner /foo,
# rw /foo owner,
# /foo owner rw,
# /foo rw owner,


# the *** proposed *** syntax for owner= and user= is
# 
# owner=<name> <whitespace> <rule>
# owner='('<names>')' <whitespace> <rule>
# 
# where the list followed the syntax for the flags value, however the list
# syntax part needs to be made consistent, ie. we either need to fix the
# flags list separator or make the list separator here the same as flags
# and also fix it for variables, etc.  switching flags to use just whitespace
# is by far the easiest.
# 
# So going with the whitespace separator we would have
# owner=jj /foo r,
# owner=(jj) /foo r,
# owner=(jj smb) /foo r,

# > capability dac_override {
# >     /file/bar rw,
# > }
# > capability chown {
# >    /file/bar (user1, user2),
# > }
# > (Are those things specific to dac_override and chown?)
# > 
# Hehe, now your veering even more into unimplemented stuff :)  Those where
# merely proposed syntax and I don't believe we are using them now.
# The idea behind those was a way to enhance the capabilities and remain
# backwards compatible.
# 
# And use the syntax for each would have to be capability (or type specific)
# 
# eg. for chown we could have a path and user
# 
#   chown /foo to (user1 user2),
# 
# but for setuid it wouldn't have a path.
#    setuid to (user1 user2)
#  
# 
# > uses ipc,
# > ipc rw /profile,
# > ipc signal w (child) /profile,
# > deny ipc signal w (kill) /profile,
# > 
# > Which keywords can apply to ipc? I'd guess audit and deny. What about 
# > owner?
# > 
# owner and user could be selectively applied but not to allow of ipc
# 
# owner doesn't really make sense for signal, but user might this is just
# another place we need to look at before we commit to the syntax.
#
# ipc may hit spring 2011
 
 
# > That all said: are there some example profiles I could use to test 
# > apparmor.vim?
# > 
# Hrmmm, yes.  The goal is to keep adding to the parser test suite, and
# get it to contain at least on example of every valid syntax and also
# example profiles of invalid syntax.  I won't say that the coverage
# is complete yet but it does have hundreds of simple examples.
# 
# it can be found in parser/tst/simple_tests/
# 
