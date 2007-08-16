%module LibAppArmor

%{
#include "aalogparse.h"
extern int aa_change_hat(const char *subprofile, unsigned long magic_token);

%}

%include "typemaps.i"
%include "aalogparse.h"
extern int aa_change_hat(const char *subprofile, unsigned long magic_token);

