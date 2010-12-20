" ----------------------------------------------------------------------
"    Copyright (c) 2005 Novell, Inc. All Rights Reserved.
"      
"    This program is free software; you can redistribute it and/or
"    modify it under the terms of version 2 of the GNU General Public
"    License as published by the Free Software Foundation.
"      
"    This program is distributed in the hope that it will be useful,
"    but WITHOUT ANY WARRANTY; without even the implied warranty of
"    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
"    GNU General Public License for more details.
"      
"    You should have received a copy of the GNU General Public License
"    along with this program; if not, contact Novell, Inc.
"      
"    To contact Novell about this file by physical or electronic mail, 
"    you may find current contact information at www.novell.com.
" ----------------------------------------------------------------------
"
" stick this file into ~/.vim/syntax/ and add these commands into your .vimrc 
" to have vim automagically use this syntax file for these directories:
"
" autocmd BufNewFile,BufRead /etc/subdomain.d/* set syntax=subdomain
" autocmd BufNewFile,BufRead */sdprofiles/*     set syntax=subdomain
" autocmd BufNewFile,BufRead */codomain-*/*/*   set syntax=subdomain

" color setup...
hi sdComment    ctermfg=lightblue
hi sdProfileName ctermfg=white
hi sdHat         ctermfg=green
hi sdGlob       ctermfg=magenta
hi sdEntryUX     ctermfg=red
hi sdEntryIX     ctermfg=cyan
hi sdEntryPX     ctermfg=green
hi sdEntryW     ctermfg=yellow
"hi sdCap	ctermfg=lightblue
"hi sdCapKey	cterm=underline ctermfg=lightblue
hi link sdCapKey  Label
hi link sdLimKey  Label
hi def link sdEntryR Normal
hi sdError      cterm=bold ctermbg=red
hi link sdFlagKey  Label
hi def link sdFlags Normal
hi sdCapDanger ctermfg=red

" always sync from the start.  should be relatively quick since we don't have
" that many rules and profiles shouldn't be _extremely_ large...
syn sync fromstart

syn keyword 	sdCapKey	chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin
syn keyword sdCapDanger sys_admin

syn keyword	sdLimKey	cpu fsize data stack core rss nofile ofile as nproc memlock locks sigpending msgqueue nice rtprio

syn keyword	sdFlagKey	complain audit debug

" highlight some invalid syntax
syn match sdError /\v.+$/ 
syn match sdError /{/ contained
syn match sdError /}/

syn match sdGlob /\v\?|\*|\{.*,.*\}|[[^\]]\+\]/

syn cluster sdEntry contains=sdEntryR,sdEntryW,sdEntryIX,sdEntryPX,sdEntryUX,sdCap,sdLim

" unconstrained entry, flag the line red
syn match  sdEntryUX /\v^\s*\/\S*\s+(l|r|w|ux)+\s*,(\s*$|(\s*#.*$)\@=)/ contained contains=sdGlob nextgroup=@sdEntry,sdComment,sdError
" standard exec entry, flag the line blue
syn match  sdEntryPX /\v^\s*\/\S*\s+(l|r|w|px)+\s*,(\s*$|(\s*#.*$)\@=)/ contained contains=sdGlob nextgroup=@sdEntry,sdComment,sdError
" standard exec entry, flag the line green
syn match  sdEntryIX /\v^\s*\/\S*\s+(l|r|w|ix)+\s*,(\s*$|(\s*#.*$)\@=)/ contained contains=sdGlob nextgroup=@sdEntry,sdComment,sdError
" if we've got u or i without x, it's an error
syn match  sdError /\v^\s*\/\S*\s+(l|r|w|u|p|i)+\s*,(\s*$|(\s*#.*$)\@=)/ contained contains=sdGlob nextgroup=@sdEntry,sdComment,sdError
" write entry, flag the line yellow
syn match  sdEntryW /\v^\s*\/\S*\s+(l|r|w)+\s*,(\s*$|(\s*#.*$)\@=)/ contained contains=sdGlob nextgroup=@sdEntry,sdComment,sdError
" Capability line
syn match  sdCap /\v^\s*capability\s+\S+\s*,(\s*$|(\s*#.*$)\@=)/ contained contains=sdCapKey,sdCapDanger nextgroup=@sdEntry,sdComment,sdError
" Rlimits
syn match  sdLim /\v^\s*set\s+rlimit\s+\S+\s*\<\=\s*(|-)[0-9]+(|K|M|G)+\s*,(\s*$|(\s*#.*$)\@=)/ contained contains=sdLimKey nextgroup=@sdEntry,sdComment,sdError
" read entry, no highlighting
syn match  sdEntryR /\v^\s*\/\S*\s+[rl]+\s*,(\s*$|(\s*#.*$)\@=)/ contained contains=sdGlob nextgroup=@sdEntry,sdComment,sdError

syn match sdProfileName /\v^\/\S+\s+(flags\=\(\S+\)\s+)=\{/ contained contains=sdProfileStart,sdHat,sdFlags
syn match sdProfileStart /{/ contained 
syn match sdProfileEnd /}/ contained
syn match sdHat /\^.\+\>/ contained
syn match sdFlags /\vflags\=\(\S+\)/ contained contains=sdFlagKey

" basic profile block...
syn region Normal start=/\v^\/\S+\s+(flags\=\(\S+\)\s+)=\{/ matchgroup=sdProfileEnd end=/}/ contains=sdProfileName,@sdEntry,sdComment,sdError

syn match sdComment /\s*#.*$/
