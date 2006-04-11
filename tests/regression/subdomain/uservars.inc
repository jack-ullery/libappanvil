# 1. Path to subdomain parser
subdomain=/sbin/apparmor_parser
#subdomain=/home/steve/svn/immunix/SubDomain/parser/subdomain_parser
#subdomain=/home/tonyj/subdomain_parser

# 2. directory to be used for temp files
# Need to be able to access this directory by the root and nobody users.
tmpdir=/tmp/sdtest.$$-$RANDOM
