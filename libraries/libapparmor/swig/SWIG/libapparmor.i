%module LibAppArmor

%{
#include "aalogparse.h"
#include "apparmor.h"

%}

%include "typemaps.i"
%include "aalogparse.h"

/* swig doesn't like the macro magic we do in apparmor.h so the fn prototypes
 * are manually inserted here
 */

extern int aa_change_hat(const char *subprofile, unsigned long magic_token);
extern int aa_change_profile(const char *profile);
extern int aa_change_onexec(const char *profile);
extern int aa_change_hatv(const char *subprofiles[], unsigned long token);
extern int aa_change_hat_vargs(unsigned long token, int count, ...);

