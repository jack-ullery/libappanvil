// Scintilla source code edit control
/** @file LexOthers.cxx
 ** Lexers for batch files, diff results, properties files, make files and error lists.
 ** Also lexer for LaTeX documents.
 **/
// Copyright 1998-2001 by Neil Hodgson <neilh@scintilla.org>
// The License.txt file describes the conditions under which this software may be distributed.

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>

#include "Platform.h"

#include "PropSet.h"
#include "Accessor.h"
#include "KeyWords.h"
#include "Scintilla.h"
#include "SciLexer.h"
#include "StyleContext.h"

static inline bool IsAWordStart(const int ch) {
        return (ch < 0x80) && (isalnum(ch) || ch == '_');
}

static inline bool IsAWordChar(const int ch) {
        return (ch < 0x80) && (isalnum(ch) || ch == '.' || ch == '_');
}
static void ColouriseAppArmorDoc(
	unsigned int startPos, 
	int length, 
	int initStyle, 
	WordList *keywordlists[],
       	Accessor &styler)
{
	initStyle = SCE_APPARMOR_DEFAULT;
	int stateHash = 19;
	int stateCap = 20;
	int pathSpaceAllowed = 0;
	int pathQuoteCount = 0;
	int chPrevNonWhite = ' ';

	StyleContext sc(startPos, length, initStyle, styler);

	for (; sc.More(); sc.Forward()) {
		
		// Handle line continuation
                if (sc.ch == '\\') {
                        if (sc.chNext == '\n' || sc.chNext == '\r') {
                                sc.Forward();
                                if (sc.ch == '\r' && sc.chNext == '\n') {
                                        sc.Forward();
                                }
                                continue;
                        }
                } 

		// Reset the states if we need to
		if (sc.state == SCE_APPARMOR_PATH) {
			if (sc.ch == '\"') {
				if (pathQuoteCount == 1) {
					// This is the end of a quote
					pathQuoteCount = 0;
					sc.ForwardSetState(SCE_APPARMOR_DEFAULT);
				} else {
					pathQuoteCount = 1;
					sc.Forward();
					sc.SetState(SCE_APPARMOR_PATH);
				}
			} else if ((sc.ch == ' ') || (sc.ch == '\t')) {
				if (pathSpaceAllowed == 1) {
					pathSpaceAllowed = 0;	
					sc.ForwardSetState(SCE_APPARMOR_PATH);
				} else if (pathQuoteCount == 1) {
					pathSpaceAllowed = 0;
					sc.ForwardSetState(SCE_APPARMOR_PATH);
				} else {
					sc.SetState(SCE_APPARMOR_PATH_TRANSITION);
				}
			} else if (sc.ch == '\\') {
				pathSpaceAllowed = 1;
				sc.SetState(SCE_APPARMOR_PATH);
			}
			
		} 
		 else if (sc.state == stateHash) {
			if (!IsAWordChar(sc.ch)) {
				char s[100];
				sc.GetCurrentLowered(s, sizeof(s));
				if (strcmp(s, "#include") == 0) {
					sc.ChangeState(SCE_APPARMOR_INCLUDE);
				} else { 
					sc.ChangeState(SCE_APPARMOR_COMMENT);
				}
			
			}
		} else if (sc.state == stateCap) {
			if (!IsAWordChar(sc.ch)) {
				char t[100];
				sc.GetCurrentLowered(t, sizeof(t));
				if (strcmp(t, "capability") == 0) {
					sc.ChangeState(SCE_APPARMOR_CAPABILITY);
				}
				sc.SetState(SCE_APPARMOR_DEFAULT);
			}
		} else if (sc.state == SCE_APPARMOR_INCLUDE) {
			if (sc.ch == '\r' || sc.ch == '\n') {
				sc.ForwardSetState(SCE_APPARMOR_DEFAULT);
			}
		} else if (sc.state == SCE_APPARMOR_COMMENT) {
			if (sc.ch == '\r' || sc.ch == '\n') {
				sc.ForwardSetState(SCE_APPARMOR_DEFAULT);
			} else if (sc.atLineStart) {
				sc.SetState(SCE_APPARMOR_DEFAULT);
			} else {
				sc.ForwardSetState(SCE_APPARMOR_COMMENT);
			}
			
		} else if (sc.state == SCE_APPARMOR_PATH_TRANSITION) {
			if (sc.ch == 'r' 
				|| sc.ch == 'w'
				|| sc.ch == 'l'
				|| sc.ch == 'x'
				|| sc.ch == 'p'
				|| sc.ch == 'u'
				|| sc.ch == 'i'
				|| sc.ch == ',') {
				sc.SetState(SCE_APPARMOR_PERMS);
			} else if (sc.ch == ' ' || sc.ch == '\t') {
				sc.SetState(SCE_APPARMOR_PATH_TRANSITION);
			} else {
				sc.SetState (SCE_APPARMOR_DEFAULT);
			}
		} else if (sc.state == SCE_APPARMOR_PERMS) {
			if (sc.ch == '\r' || sc.ch == '\n' || sc.ch == '{') {
				sc.SetState(SCE_APPARMOR_DEFAULT);
			}
		}

		// See if we need to enter a new state
		if (sc.state == SCE_APPARMOR_DEFAULT) {
			if (sc.ch == '#') {
				if (sc.chNext == ' ') {
					// This'll have to be a comment
					sc.SetState(SCE_APPARMOR_COMMENT);
				} else {
					sc.SetState(stateHash);
				}
			}  else if (sc.ch == '/') {
				sc.SetState(SCE_APPARMOR_PATH);
			} else if (IsAWordStart(sc.ch)) {
				sc.SetState(stateCap);
			} else if (sc.ch == '\"') {
				if (sc.chNext == '/') {
					pathQuoteCount = 1;
					sc.SetState(SCE_APPARMOR_PATH);
				}
			} 
		}

		if (sc.atLineEnd) {
			chPrevNonWhite = ' ';
		}

		if (!IsASpace(sc.ch)) {
			chPrevNonWhite = sc.ch;
		}
	}
	sc.Complete();
}  


static const char * const appArmorWordListDesc[] = {
	"Keywords",
	0
};

LexerModule lmAppArmor(SCLEX_APPARMOR, ColouriseAppArmorDoc, "apparmor", 0, appArmorWordListDesc);
