lexer grammar AppArmor;
options {
  language=C;

}
@members {
	/* startOfLine, like the name suggests, tracks
	 * whether or not a non '#' character has been used on a line,
	 * in order to ultimately figure out if a comment is a "start
	 * of line" comment or an "end of line" comment.
	 * 
	 * We can't use the character position for this because a position
	 *  of '10' spaces could count as not being the start of the line.
	 */
	int startOfLine = 0;	
	
	/* inVariable and equalSign are used by the NEWLINE lexer rule to
	 * figure out if a NEWLINE should be returned to the parser. 
	 * inVariable is set by the lexer when a variable token is found,
	 * and equalSign is set when an EQUALS token is found.  If both 
	 * integers equal 1, it is assumed that we're dealing with a variable
	 * assignment.  This approach is used rather than adding another
	 * syntactic predicate to the lexer, as syntactic predicates should
	 * be avoided as often as possible.
	 *
	 * For a full explanation of why the parser needs the NEWLINE token
	 * when a variable assignment occurs, please see the last comment
	 * in the 'variableAssign' parser rule.
	 */
	int inVariable = 0;
	int equalSign = 0;
	
	/* inInclude is used by the NEWLINE lexer rule to figure out when to
	 * kick off a new lexer stream reading from an d file.
	 * There's probably a better way to do this, but in the meantime,
	 * a full description is commented in the parser include rule.
	 */
	 int inInclude = 0;
	 char *lexerIncludeFile = NULL;

	 /* When we read in an include file, we push a new input stream onto
	  * the lexer's input stack.   It's helpfully designed so that when the
	  * stream runs out of data, it bounces back to the previous stream.
	  * However, the include stream isn't actually closed.  In order to
	  * close them, we'll track a vector of streams that we open as we 
	  * encounter new files to be included, and then close them 
	  * right before startParse returns.  It's important to never close
	  * a stream before you're certain that parsing is complete, since 
	  * tokens don't actually contain the text, they just point into
	  * the input stream.
	  */
	 pANTLR3_VECTOR streamVector;
	 void init_stream_vector(void)
	 {
	 	streamVector = antlr3VectorNew(0);
	 }
	 void close_streams (void)
	 {
	 	ANTLR3_UINT64 vsize, count;
		pANTLR3_INPUT_STREAM tmp;
		vsize = streamVector->size(streamVector);
		/* The vector index is 1 based.  Decrement it
		 * so ANTLR doesn't shuffle entries around.
		 */
		for (count = vsize; count != 0; count--)
		{
			tmp = streamVector->get(streamVector, count);
			tmp->close(tmp);
			streamVector->remove(streamVector, count);
		}
		streamVector->free(streamVector);
	 }
	 

}
@header {
#include "libaaprofileparse.h"
#include "antlr/antlr3collections.h"

void init_stream_vector(void);
void close_streams (void);
}

T32 : 'true' ;
T33 : 'false' ;
T34 : 'audit' ;
T35 : 'version' ;
T36 : 'encoding' ;
T37 : 'disabled' ;
T38 : 'complain' ;
T39 : 'profile' ;
T40 : 'flags' ;
T41 : 'fold_hats' ;
T42 : ',' ;
T43 : 'change_profile' ;
T44 : 'capability' ;
T45 : 'if' ;
T46 : 'else' ;
T47 : 'error' ;
T48 : 'undef' ;
T49 : 'warn' ;
T50 : 'not' ;
T51 : 'exists' ;
T52 : 'defined' ;
T53 : 'and' ;
T54 : 'or' ;
T55 : 'network' ;
T56 : 'conntrack' ;
T57 : 'inet' ;
T58 : 'ax25' ;
T59 : 'netrom' ;
T60 : 'bridge' ;
T61 : 'atmpvc' ;
T62 : 'x25' ;
T63 : 'inet6' ;
T64 : 'rose' ;
T65 : 'netbeui' ;
T66 : 'security' ;
T67 : 'key' ;
T68 : 'packet' ;
T69 : 'ash' ;
T70 : 'econet' ;
T71 : 'atmsvc' ;
T72 : 'sna' ;
T73 : 'irda' ;
T74 : 'pppox' ;
T75 : 'wanpipe' ;
T76 : 'bluetooth' ;
T77 : 'stream' ;
T78 : 'dgram' ;
T79 : 'seqpacket' ;
T80 : 'rdm' ;
T81 : 'raw' ;
T82 : 'tcp' ;
T83 : 'udp' ;
T84 : 'ipx' ;
T85 : 'appletalk' ;
T86 : 'sctp' ;
T87 : '&' ;
T88 : 'connect' ;
T89 : 'accept' ;
T90 : 'connected' ;
T91 : 'send' ;
T92 : 'recv' ;
T93 : 'to' ;
T94 : 'from' ;
T95 : 'endpoint' ;
T96 : 'via' ;
T97 : 'limit' ;

// $ANTLR src "AppArmor.g" 1280
NEWLINE
	@after {
		
		if (inInclude == 1)
		{
		/* Load the new input stream  */
			inInclude = 0;
			startOfLine = 0;
			equalSign = 0;
			inVariable = 0;
			
			int lexerLen = strlen(lexerIncludeFile);
			int dirLen = strlen(AA_PROFILE_DIR);
			char *tmp = (char *) malloc (lexerLen + dirLen + 1);
			snprintf(tmp, lexerLen + dirLen + 1, 
				"\%s\%s", AA_PROFILE_DIR, lexerIncludeFile);
			free(lexerIncludeFile);
			lexerIncludeFile = tmp;
			
			$channel = HIDDEN;
			if (access(tmp, R_OK) != 0)
			{
				printf("Exception\n");
				CONSTRUCTEX();
				EXCEPTION->type = 33;
				EXCEPTION->name = "Invalid Include";
				EXCEPTION->message = tmp;
				//free(tmp);
				goto ruleNEWLINEEx;
			}
			
			pANTLR3_INPUT_STREAM input;
			input = antlr3AsciiFileStreamNew((pANTLR3_UINT8) tmp);
			free(tmp);
			streamVector->add(streamVector, input, NULL);
			PUSHSTREAM(input);
			
		}
	}
	:('\r\n' 
          |'\r' 
          |'\n')
 	  {
	  	if (((inVariable == 1) && (equalSign == 1)) 
		   || (startOfLine == 0))
		{
		  	$type = NEWLINE;
		}
		else
		{
			$channel = HIDDEN;
		}
		startOfLine = 0;
		equalSign = 0;
		inVariable = 0;
	  }
	  ;

/* Token definition */
// $ANTLR src "AppArmor.g" 1339
LESS_THAN	: { startOfLine = 1; }	'<' ;
// $ANTLR src "AppArmor.g" 1340
GREATER_THAN	: { startOfLine = 1; }	'>' ;
// $ANTLR src "AppArmor.g" 1341
LEFT_BRACE	: { startOfLine = 1; }	'{' ;
// $ANTLR src "AppArmor.g" 1342
RIGHT_BRACE	: { startOfLine = 1; }	'}' ;
// $ANTLR src "AppArmor.g" 1343
AT		: { startOfLine = 1; }	'@' ;
// $ANTLR src "AppArmor.g" 1344
DOLLAR		: { startOfLine = 1; }	'$' ;
// $ANTLR src "AppArmor.g" 1345
LEFT_PAREN	: { startOfLine = 1; }	'(' ;
// $ANTLR src "AppArmor.g" 1346
RIGHT_PAREN	: { startOfLine = 1; }	')' ;
// $ANTLR src "AppArmor.g" 1347
PLUS		: '+' ;
// $ANTLR src "AppArmor.g" 1348
EQUALS		: { equalSign = 1; } '=' ;

/* Disambiguate the #include from the #comments */
// $ANTLR src "AppArmor.g" 1351
COMMENT_OR_INCLUDE
	: '#' 
	(
	  (('include ')=>'include ')
		{ $type=INCLUDE; inInclude = 1; }
	| COMMENT
		{
			if (startOfLine == 1)
			{
				$type=EOL_COMMENT;
			}
			else
			{
				startOfLine = 1;
				$type=SOL_COMMENT;
			}
		}
	)
	;

// $ANTLR src "AppArmor.g" 1371
INCLUDE
	: 'include'
		{ $type=INCLUDE; inInclude = 1;}
	;

/* For some reason, ANTLR 3 doesn't like imaginary tokens
   (although all of the docs say it does.  So define these two
   fragments to prevent hassle.
*/
// $ANTLR src "AppArmor.g" 1380
fragment
SOL_COMMENT : '#' COMMENT
	;

// $ANTLR src "AppArmor.g" 1384
fragment
EOL_COMMENT : '#' COMMENT
	;


/* This rule will eat up anything after a # */

// $ANTLR src "AppArmor.g" 1391
fragment
COMMENT
	: (~('\n'|'\r'))*
	;

// $ANTLR src "AppArmor.g" 1396
fragment
ANYTHING_NOT_QUOTED
	: (~'"')*// "
	;
	
// $ANTLR src "AppArmor.g" 1401
QUOTED_STRING 
	: '"' f=ANYTHING_NOT_QUOTED '"' //"
	{
		$type = QUOTED_STRING;
		/* If it's an include file, save the token text for NEWLINE */
		if (inInclude == 1)
			lexerIncludeFile=strdup((char *) $f.text->chars);
		startOfLine = 1;
	}
	;

// $ANTLR src "AppArmor.g" 1412
fragment
PATH 
	: '/' ('a'..'z'|'A'..'Z'|'_'|'*'| '[' | ']'
		|'0'..'9'|'-'|'.'|'/'|'\u0080'..'\u00ff')*
		{ startOfLine = 1; }
	;

// $ANTLR src "AppArmor.g" 1419
UNQUOTED_PATH
	: p=PATH
	{
		if (inInclude == 1)
			lexerIncludeFile=strdup((char *) $p.text->chars);	
	}
	;

/* Unfortunately, in order to keep variable assignments from becoming
   a great big mess (see comment at the end of 'variableAssign')
   we have to track NEWLINE.  Which means that we have to figure out
   when a variable is being assigned a value or if it is being used.
*/

// $ANTLR src "AppArmor.g" 1433
LIST_VAR_START 
	: '@' '{'
	{ startOfLine = 1; inVariable = 1; }
	;
	
// $ANTLR src "AppArmor.g" 1438
BOOL_VAR_START
	: '$' '{'
	{ startOfLine = 1; inVariable = 1; }
	;

// $ANTLR src "AppArmor.g" 1443
RULE
	: 	('r' 
		|'w' /* TODO: 'w' and 'a' should be mutually exclusive(?) */
		|'l' 
		|'m'
		|'k'
		|'a'
		|'i''x' 
		|'p''x' 
		|'u''x'
		|'P''x'
		|'U''x'
		)+ { startOfLine = 1; }
	;
	
// $ANTLR src "AppArmor.g" 1458
fragment 
IDENT_START
	: 'a'..'z'
	|'A'..'Z'
	|'_'
	|'0'..'9'
	|'\u0080'..'\u00ff'
	;

// $ANTLR src "AppArmor.g" 1467
fragment
IDENT_CONTINUE
	:  IDENT_START
	| '*'
	|'.'
	|'-'
	|':'
	|'/'
	;

// $ANTLR src "AppArmor.g" 1477
fragment
REAL_IDENT
	: IDENT_START ( IDENT_CONTINUE )*
	;
// $ANTLR src "AppArmor.g" 1481
IDENT
	: f=REAL_IDENT
	{
		if (inInclude == 1)
			lexerIncludeFile=strdup((char *) $f.text->chars);
		startOfLine = 1;
		$type = IDENT; 
	}
 	;


// $ANTLR src "AppArmor.g" 1492
WS:	(' '|'\t')+ { $channel = HIDDEN; };
