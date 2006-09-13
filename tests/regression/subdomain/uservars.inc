# 1. Path to apparmor parser
subdomain=/sbin/apparmor_parser
#subdomain=/home/steve/svn/immunix/SubDomain/parser/subdomain_parser
#subdomain=/home/tonyj/subdomain_parser

# 2. additional arguments to the apparmor parser
parser_args=-q

# 3. directory to be used for temp files
# Need to be able to access this directory by the root and nobody users.
tmpdir=/tmp/sdtest.$$-$RANDOM
