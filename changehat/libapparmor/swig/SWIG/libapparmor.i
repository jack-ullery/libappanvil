%module LibAppArmor

%{
#include "aalogparse.h"
extern int change_hat (const char *subprofile, unsigned int magic_token);

%}

%include "typemaps.i"
%include "aalogparse.h"
extern int change_hat (const char *subprofile, unsigned int magic_token);

