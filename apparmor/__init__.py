# ------------------------------------------------------------------
#
#    Copyright (C) 2011-2012 Canonical Ltd.
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------
import gettext
import locale

def init_localisation():
    locale.setlocale(locale.LC_ALL, '')
    #If a correct locale has been provided set filename else let an IOError be raised
    filename = '/usr/share/locale/%s/LC_MESSAGES/apparmor-utils.mo' % locale.getlocale()[0]
    try:
        trans = gettext.GNUTranslations(open(filename, 'rb'))
    except IOError:
        trans = gettext.NullTranslations()
    trans.install()

init_localisation()
