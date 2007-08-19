/* TODO:
	* Write an (A)BNF grammar
	* Parse hatnames out?
	* Better error reporting
	* Exceptions from invalid include files aren't being reported
	  correctly, they're coming through as "mismatched token" (?).
	* The network rules just know about IDENT tokens, and don't break
	  data like "127.0.0/24:80" into anything, it's just a text string.
	  That is an area that needs to be improved.
*/

/* UPDATING THE ANTLR SUPPORT LIBRARY:
 *
 * We build the ANTLR support library in with libaaprofile parse.  To upgrade
 * simply download the latest version of ANTLR3, unzip the file in 
 * $(SRCDIR)/runtime/C/dist, copy the files from the src/ and include/ dir
 * from there to src/antlr.  Rebuild.  No further changes should be necessary.
 */

/*
 * A General Guide To Adding Syntax
 *
 * As an example of how to add syntax to the parser & the backend parse tree,
 * I'll use IPC as a jumping off point.
 *
 * Adding a new set of IPC rules involves two things: adding the syntax in the
 * ruleExpr parser section, and adding a new element node (with it's supporting
 * allocation/deallocation functions) to the parse tree.
 *
 * It's a simple process:
 *
 * - Create a new rule, say 'ipcRule' that specifies the grammar you want to
 *   allow.  Have this rule return a ParseNode.
 * - Create a new IPC struct in Nodes.h that contains the various data fields.
 * - Add new_ipc_node() and free_ipc_node() to DataNodes.(h & c) to handle
 *   the memory allocation and deallocation.
 * - Add an ELEMENT_IPC entry to the NodeTypes enum in Types.h
 * - Have ipcRule attach this new IPC struct to the ParseNode it will return.
 * - Add ipcRule to ruleExpr.
 *
 * The process is the same for adding elements that can be used outside of 
 * rule blocks.
 * 
 * Something to keep in mind: Unlike most parser generators, ANTLR 3 doesn't 
 * necessarily need specific tokens to be fed to it from the lexer - for the 
 * most part you can get away with adding new keywords directly in the parser.
 * A good example of this is the network rules, which consist entirely of 
 * parser keywords, and IDENT tokens.
 */

grammar AppArmor;

options {
	language=C;
	}
tokens {
	SOL_COMMENT;
	EOL_COMMENT;
}

@header {
	#include "libaaprofileparse.h"
	#include "AppArmorLexer.h"
	#include "Exceptions.h"
	#include <stdio.h>
}

@lexer::header {
#include "libaaprofileparse.h"
#include "antlr/antlr3collections.h"

void init_stream_vector(void);
void close_streams (void);
}
/* TODO - Make this thread safe by using a dynamic scope */
@lexer::members {
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

/* Override ANTLR error handling.  Rather than recreate the ANTLR way
 * of doing exceptions in C, which involves gotos and the code below,
 * we set a flag in the root parse node, and attach an error struct
 * for reporting.
*/


@rulecatch {

	if (HASEXCEPTION())
	{
		if (mpTree != NULL)
		{
			ParseError *error = new_parse_error();
			if (mpTree->pError != NULL)
				free_parse_error(mpTree->pError);
			mpTree->mError = 1;
			mpTree->pError = error;
			error->mLine = EXCEPTION->line;
			error->mPos = EXCEPTION->charPositionInLine;
			
			if (EXCEPTION->name != NULL)
			error->pName = strdup(EXCEPTION->name);
			
			if (EXCEPTION->message != NULL)
			error->pMessage = strdup((char *) EXCEPTION->message);
		}
	}
}

@members {
	ParseNode *mpTree;
	Comment *mpCommentBlock;
	int mNewlineCount;
	pANTLR3_STRING_FACTORY factory;
		
	void AttachCommentBlock(ParseNode *node)
	{
		if (mpCommentBlock != NULL)
		{
			node->pCommentBlock = mpCommentBlock;
			mpCommentBlock = NULL;
		}		
	}
}


/* The main entry into the parser */
startParse returns [ParseNode *returnTree]
	@init { 
		init_stream_vector();
		File *topFileNode = new_file_node();
		mpTree = new_parse_node(ELEMENT_FILE, NULL);
		mpTree->pData = topFileNode;
		mpTree->pVariableList = NULL;
		$returnTree = mpTree;
		factory = antlr3StringFactoryNew();
	}
	:
	( appArmorProfile )* EOF
	{
		close_streams();
		factory->close(factory);
	}
	;

appArmorProfile
	: ( newlineRule )
	| ( includeExpr { mNewlineCount = 0; } )
	| ( startOfLineComment { mNewlineCount = 0; } )
	| ( optionExpr { mNewlineCount = 0; } )
	| ( profileExpr { mNewlineCount = 0; } )
	| ( variableAssign { mNewlineCount = 0; } )
	;

/* Relevant syntax: support functionality for comment tracking.

   We keep track of newlines in order to tell when a comment block
   should be attached to the following node, or if it should be it's own.
   For example:
   
   # Comment
   # Block
   # One
   /path/to/something { }
   
   Would have Comment Block One attached as it's 'block comment'.
   If there were one or more newlines between the comment and the path,
   the comment block would be it's own node.
   
   Note that the NEWLINE token is only passed up when a newline character
   is encountered at the start of a line or if a value is being assigned
   to a variable.
*/

newlineRule
	: NEWLINE
	{
		if (mpCommentBlock != NULL)
		{
			ParseNode *newNode;
			newNode = new_parse_node(ELEMENT_COMMENT, mpTree);
			newNode->pData = mpCommentBlock;
			THROW_IF_NULL(newNode,rulenewlineRuleEx);
			add_parse_node_child(mpTree, newNode);
			mpCommentBlock = NULL;
		}
	}
	;

/* Relevant syntax: A comment that appears before any other syntax.

   This rule handles any comment that appears first on a line, which
   will either be attached to a node immediately following it, or 
   will become a unique node in the parse tree in it's own right, as assigned
   in 'newlineRule'.
*/
startOfLineComment
	: comment=SOL_COMMENT
	{
		/* If a block comment doesn't currently exist,
		 * assign this new found comment to be the start of one.
		 * otherwise, append it to the block comment we're already
		 * keeping track of.
		 *
		 * NOTE: Notice how \%s is escaped?  If you don't do that,
		 * ANTLR will complain about it because it clashes with
		 * StringTemplate's business.
		 */

		if (mpCommentBlock == NULL)
		{
			mpCommentBlock = new_comment_node((char *) $comment.text->chars);
			THROW_IF_NULL(mpCommentBlock,rulestartOfLineCommentEx);
		}
		else
		{
			int len1 = strlen((char *) mpCommentBlock->pCommentText);
			int len2 = $comment.text->len;
			char *tmp = (char *) malloc(len1 + len2 + 3);
			snprintf(tmp, len1 + len2 + 2, "\%s\n\%s", 
						mpCommentBlock->pCommentText,
						$comment.text->chars);
			free(mpCommentBlock->pCommentText);
			mpCommentBlock->pCommentText = tmp;
		}
	}
	;

/* Relevant syntax: any comment that comes after another valid token

   "end of line" comments are handled explicitly at every point in
   the parser that one might legitimately occur.  Unfortunately,
   using hidden token streams in ANTLR 2 didn't help at all, so I decided
   to be explicit about it.
*/
endOfLineComment[Comment *a]
	: comment=EOL_COMMENT
	{
		/* The rules that call this one should be passing in
		 * their ParseNode->pEOLComment pointer as $a.  If it's NULL,
		 * great - allocate it and assign the text.  This is the most
		 * likely occurance.  In some cases, EOL comments will need
		 * to be appended to each other, like this:
		 * 
		 *
		 * /path/to #comment1
		 * { #comment2
		 * } #comment 3
		 * 
		 * those will all form a large EOL comment block attached
		 * to the Group node.  So in that case, append the text to $a.
		 */
		if ($a->pCommentText == NULL)
		{
			$a->pCommentText = strdup((char *) $comment.text->chars);
		}
		else
		{

			int len1 = strlen((char *) $a->pCommentText);
			int len2 = $comment.text->len;
			char *tmp = (char *) malloc(len1 + len2 + 3);
			snprintf(tmp, len1 + len2 + 2, "\%s\n\%s", 
						$a->pCommentText,
						$comment.text->chars);
			free($a->pCommentText);
			$a->pCommentText = tmp;
		}
	}
	;

/* Relevant syntax: '#include <file>' or 'include <file>'

   This rule only creates an Include node in the parse tree.  The actual
   work of opening an include file and sucking it in for parsing is done
   in the lexer using a really annoying way of going about things:
   	* The INCLUDE rule sets "inInclude = 1"
	* When the lexer comes across IDENT, UNQUOTED_PATH or QUOTED_STRING
	  and inInclude is 1, it caches the file path
	* When the end of that rule is reached, and it hits the NEWLINE
	  rule in the lexer, the lexer creates a new lexer input and switches
	  from the current one to it.

    This approach has the nice benefit of not duplicating token streams
    or parsers, but it's also not a very clean way of doing it.  You may
    be wondering why we don't just call parse_file() again in 'includeExpr'
    and the only answer I can give you is "that just doesn't work" - 
    it obliterates the current parser and fucks everything up.  If you have
    some free time, you might want to look into it.
*/
includeExpr
	@init { Comment *newComment = new_comment_node(NULL); }
	: INCLUDE (LESS_THAN (include=IDENT|include=UNQUOTED_PATH) GREATER_THAN
	| include=QUOTED_STRING)
	( endOfLineComment[newComment] )?
	{
		Include *includeFile = new_include_node();
		THROW_IF_NULL(includeFile,ruleincludeExprEx);
		ParseNode *includeNode;
		includeNode = new_parse_node(ELEMENT_INCLUDE, mpTree);
		THROW_IF_NULL(includeNode,ruleincludeExprEx);
		
		includeNode->pData = includeFile;
		includeNode->pEOLComment = newComment;
		AttachCommentBlock(includeNode);
		
		/* if this is a QUOTED_STRING, strip the quotes out using
		 * the ANTLR_STRING_struct substring function.
		 * Yes, I know it looks horrible.
		 */
		if ($include.text->charAt($include.text, 0) == '\"') /* " */
			includeFile->pIncludeFile = 
				strdup((char *) $include.text->subString
						($include.text,	1, 
						$include.text->len - 1)->chars);
		else
			includeFile->pIncludeFile = strdup((char *) $include.text->chars);
		
		add_parse_node_child(mpTree, includeNode);
	}
	;

/* Relevant syntax: @{variable} = "one" "two" @{variable2}
 */
variableAssign
	@init {
		char *name = NULL;
		char *valueString = NULL;

		Comment *newComment = new_comment_node(NULL);

		VariableAssignment *varAssign;
		varAssign = new_variable_assignment_node();
		THROW_IF_NULL(varAssign,rulevariableAssignEx);
		
		ParseNode *varNode;
		varNode = new_parse_node(ELEMENT_VARIABLE_ASSIGNMENT, mpTree);
		varNode->pData = varAssign;
		varNode->pEOLComment = newComment;
		AttachCommentBlock(varNode);

		if (mpTree->pVariableList == NULL)
			mpTree->pVariableList = new_variable_list();

	}
	:
	( LIST_VAR_START varList=IDENT RIGHT_BRACE
		{ name = strdup((char *) $varList.text->chars); }
		( PLUS { varAssign->mPlusEquals = 1; } )?
	EQUALS
	{
		/* Clear out any existing entries if it is not a +=
		 * assignment.
		 */
		if ((mpTree->pVariableList != NULL) 
		    && (varAssign->mPlusEquals == 0))
			mpTree->pVariableList = 
				del_variable_list_by_name(mpTree->pVariableList,
							name);
	}
	/* The next two rules are part of a 0+ loop. */
	/* Assign or append a string to the variable */
	( (incomingString=IDENT|incomingString=QUOTED_STRING|incomingString=UNQUOTED_PATH)
	{ 
	
		/* Insert the entry */

		VariableListEntry *newEntry = new_variable_list_entry();
		newEntry->mIsBoolValue = 0;
		newEntry->pName = strdup(name);
		newEntry->mValues.pValue = strdup((char *) $incomingString.text->chars);
		add_variable_list_entry(mpTree->pVariableList, newEntry);
	
		/* If this is the first iteration (or the only one)
		 * of a list of variables being assigned, insert it.
		 * Otherwise, append it.
		 */
		if (valueString == NULL)
		{
			valueString = (char *) malloc($incomingString.text->len + 1);
			strncpy(valueString, (char *)
				$incomingString.text->chars,
				$incomingString.text->len + 1);
		}
		else
		{
			int len1 = strlen(valueString);
			int len2 = $incomingString.text->len;
			char *tmp = (char *) malloc(len1 + len2 + 2);
			sprintf(tmp, "\%s \%s", valueString, 
						$incomingString.text->chars);
			free(valueString);
			valueString = tmp;
		}

	}
	| LIST_VAR_START incomingString=IDENT RIGHT_BRACE	
	{

		/* insert the contents of "incomingString" from the 
		 * variable list into the "name" entry.
		 */
		append_variable_list_values(mpTree->pVariableList,
					name,
					(char *)$incomingString.text->chars);

		if (valueString == NULL)
		{
			valueString = (char *) malloc($incomingString.text->len + 4);
			snprintf(valueString, $incomingString.text->len + 4, 
						"@{\%s}",
						$incomingString.text->chars);
		}
		else
		{
			int len1 = strlen(valueString);
			int len2 = $incomingString.text->len;
			char *tmp = (char *) malloc(len1 + len2 + 5);
			sprintf(tmp, "\%s @{\%s}", valueString, 
						$incomingString.text->chars);
			free(valueString);
			valueString = tmp;
		}
	}
	)*
	/* Handle a boolean assignment */
	| BOOL_VAR_START boolVar=IDENT RIGHT_BRACE 
	  { 
	  	name = strdup((char *) $boolVar.text->chars);
		varAssign->mIsBoolValue = 1;
	  } EQUALS
		( 'true'
		{
			if (valueString != NULL) free(valueString);
			valueString = strdup(" = true");
			VariableListEntry *newEntry = new_variable_list_entry();
			newEntry->mIsBoolValue = 1;
			newEntry->pName = strdup(name);
			newEntry->mValues.mBoolValue = 1;
			add_variable_list_entry(mpTree->pVariableList,
							newEntry);

		}
		| 'false'
		{
			if (valueString != NULL) free(valueString);
			valueString = strdup(" = false");
			VariableListEntry *newEntry = new_variable_list_entry();
			newEntry->mIsBoolValue = 1;
			newEntry->pName = strdup(name);
			newEntry->mValues.mBoolValue = 0;
			add_variable_list_entry(mpTree->pVariableList,
							newEntry);
		}
		)
	)
	/* Track the newline as part of the rule otherwise something like:
	 *	@{var} = @{var2}
	 *	@{var3} = @{var4}
	 * will come across in a token stream as:
	 *      @{var} = @{var2} {@var3} = @{var4}
	 * and cause the parser to choke on the second '='.  We, of course,
	 * don't want to track the newline on other rules.
	 */
	( NEWLINE | endOfLineComment[newComment] )
	{
		varAssign->pName = name;
		varAssign->pValue = valueString;
		add_parse_node_child(mpTree, varNode);
	}
	;

/* Relevant syntax: option version 2.0

   This syntax isn't in use yet, but maybe someone will find a use for it 
   someday.
*/
optionExpr
	@init {
		Option *option = new_option_node();
		THROW_IF_NULL(option,ruleoptionExprEx);
		Comment *newComment = new_comment_node(NULL);
		ParseNode *optionTree = new_parse_node(ELEMENT_OPTION, mpTree);
		THROW_IF_NULL(optionTree,ruleoptionExprEx);
		optionTree->pData = option;
		optionTree->pEOLComment = newComment;
		AttachCommentBlock(optionTree);
	}
	:
	( 'audit' ('true' { option->mValue.mBoolValue = 1; }
		   |'false' { option->mValue.mBoolValue = 0; } )
	{ option->mOptionType = OPTION_AUDIT; }
	| 'version' (ver=IDENT | ver=QUOTED_STRING)
	{
		option->mOptionType = OPTION_VERSION;
		option->mValue.pCharValue = strdup((char *) $ver.text->chars);
	}
	| 'encoding' (enc=IDENT | enc=QUOTED_STRING)
	{
		option->mOptionType = OPTION_ENCODING;
		option->mValue.pCharValue = strdup((char *) $enc.text->chars);
	}
	| 'disabled' ('true' { option->mValue.mBoolValue = 1; }
		     |'false' { option->mValue.mBoolValue = 0; } )
	{ option->mOptionType = OPTION_DISABLED; }
	| 'complain' ('true' {option->mValue.mBoolValue = 1; }
		     |'false'{ option->mValue.mBoolValue = 0; })
	{ option->mOptionType = OPTION_COMPLAIN; }
	)
	{ add_parse_node_child(mpTree, optionTree); }
	( endOfLineComment[newComment] )?
	;

/* Relevant syntax:
	/path/to/program flags=(complain) { }
	/path/to/program (complain) { }
	profile /path/to/program { }

    This is the main profile block.  
*/
profileExpr
	@init
	{
		ParseNode *profileTree; /* This node */
		Group *profileElement;
		char flags = 0;
		Comment *newComment = new_comment_node(NULL);
		profileElement = new_group_node(ELEMENT_GROUP_INVALID);
		THROW_IF_NULL(profileElement,ruleprofileExprEx);
		profileTree = new_parse_node(ELEMENT_GROUP, mpTree);
		THROW_IF_NULL(profileTree,ruleprofileExprEx);
		profileTree->pData = profileElement;
		profileTree->pEOLComment = newComment;
		AttachCommentBlock(profileTree);
		add_parse_node_child(mpTree, profileTree);
	}	
	: 
	(   (path=UNQUOTED_PATH|path=QUOTED_STRING)
		{ profileElement->mGroupType = ELEMENT_GROUP_SUBPROFILE; }
	    | 'profile' path=IDENT
	    	{profileElement->mGroupType = ELEMENT_GROUP_TRANSITION_PROFILE;}
	)
		{ profileElement->pIdentifier = strdup((char *) $path.text->chars); }
	/* Are there any flags? */
	( ('flags' EQUALS)? LEFT_PAREN
		( 'complain' { flags |= GROUP_FLAG_COMPLAIN; }
		| 'disabled' { flags |= GROUP_FLAG_DISABLED; }
		| 'audit' { flags |= GROUP_FLAG_AUDIT; }
		| 'fold_hats' { flags |= GROUP_FLAG_FOLD_HATS; })*
		RIGHT_PAREN
	)?
	( endOfLineComment[newComment] )?
	LEFT_BRACE ( endOfLineComment[newComment] )?
	incomingRuleTree=ruleExpr
	{
		if ($incomingRuleTree.ruleExprTree != NULL)
			add_parse_node_child(profileTree,
						$incomingRuleTree.ruleExprTree);
	}
	RIGHT_BRACE ( endOfLineComment[newComment] )?
	;

/* This sub-rule handles all of the parts that go between the braces
   in a profile definition.
*/
ruleExpr returns [ParseNode *ruleExprTree]
	@init{
		ParseNode *retTree = NULL;
		ParseNode *conditionalParent = NULL;
	}
	:
	( newlineRule
	| startOfLineComment
	| includeExpr
	| ( incomingRule = accessRule
	  | incomingRule = capabilityRule 
	  | incomingRule = auditRule
	  | incomingRule = changeProfileRule
	  | incomingRule = networkRule
	  ) {
	  	conditionalParent = NULL;
		/* We need to return a list of nodes, which is what this
		 * is all about.
		 */
		if (retTree == NULL)
			retTree = $incomingRule.tree;
		else
			add_parse_node_sibling(retTree, $incomingRule.tree);
	    }

	| incomingIfTree=conditionalIfExpr
	  {
		conditionalParent = $incomingIfTree.tree;
		
		if (retTree == NULL)
			retTree = conditionalParent;
		else
			add_parse_node_sibling(retTree, conditionalParent);
	  } 
	| incomingElseTree = conditionalElseExpr
	  {
	  	/* If conditionalParent is NULL, that means that
		 * one of the other rules has been called in between
		 * an if and an else, and we simply can't accept that.
		 */
		if (conditionalParent != NULL)
		{
		 	Conditional *tmp = (Conditional *) conditionalParent->pData;
			tmp->pElseBranch = $incomingElseTree.tree;
		}
		else
		{
			 THROW_PARSER_EXCEPTION("else missing an if",ruleruleExprEx);
		}
	  }
	)* { $ruleExprTree = retTree; }/* end of the rule loop */
	;

/* Relevant syntax: /path/to/something rw,

   This is for resource access rules
*/
accessRule returns [ParseNode *tree]
	@init
	{
		$tree = new_parse_node(ELEMENT_RULE, mpTree);
		THROW_IF_NULL($tree,ruleaccessRuleEx);
		
		Comment *newComment = new_comment_node(NULL);
		
		Rule *newRule = new_rule_node();
		THROW_IF_NULL(newRule,ruleaccessRuleEx);
		$tree->pData = newRule;
		$tree->pEOLComment = newComment;
		AttachCommentBlock($tree);
	}
	:( path=accessPath rule=RULE ','
	| rule=RULE path=accessPath ',' )
	{
		newRule->pResource = strdup((char *) $path.path->chars);
		/* If it's a QUOTED_STRING, it won't have a pExpandedPath.
		 */
		if ($path.expandedPath->chars != NULL)
		newRule->pExpandedResource = strdup((char *) $path.expandedPath->chars);
		newRule->pPermString = strdup((char *) $rule.text->chars);
		/* TODO: convert permstring into a bitmask */
	}
	( endOfLineComment[newComment] )?
	;

/* As paths can either be QUOTED_STRINGS or a combination of variables
 * and unquoted paths, we break it up into a separate rule.
 */ 
accessPath returns [pANTLR3_STRING path, pANTLR3_STRING expandedPath]
	@init {
		$path = factory->newRaw(factory);
		$expandedPath = factory->newRaw(factory);
	}
	: u=QUOTED_STRING
	{
		$path->setS($path, $u.text);
	}
	|
	( LIST_VAR_START u=IDENT RIGHT_BRACE
	    {
	    	$path->append($path, "${");
		$path->appendS($path, $u.text);
		$path->append($path, "}");
		/* Expand the variables and insert them */
		VariableList *list = find_variable_list_by_name
					(mpTree->pVariableList,
					(char *) $u.text->chars);
		if (list != NULL)
		{
			VariableListEntry *tmp = list->pFirstEntry;
			while (tmp != NULL)
			{
				if (tmp->mIsBoolValue == 1) break;
				if (tmp->mValues.pValue == NULL) break;
				
				$expandedPath->append($expandedPath,
							tmp->mValues.pValue);
				tmp = tmp->pNext;
			}
		}
	    }
	  | u=UNQUOTED_PATH
	    {
	    	$path->appendS($path, $u.text);
		$expandedPath->appendS($expandedPath, $u.text);
	    }
	  )+
	;
/* Relevant syntax: change_profile /profile,
*/

changeProfileRule returns [ParseNode *tree]
	@init {
		ChangeProfile *newProfile = new_change_profile_node();
		THROW_IF_NULL(newProfile,rulechangeProfileRuleEx);
		Comment *newComment = new_comment_node(NULL);
		THROW_IF_NULL(newComment,rulechangeProfileRuleEx);
		$tree = new_parse_node(ELEMENT_CHANGE_PROFILE, mpTree);
		THROW_IF_NULL($tree,rulechangeProfileRuleEx);
		$tree->pData = newProfile;
		$tree->pEOLComment = newComment;
		AttachCommentBlock($tree);
	}
	: 'change_profile' path=UNQUOTED_PATH
	{ newProfile->pProfile = strdup((char *) $path.text->chars); }
	;

/* Relevant syntax: capability one two three,
 */
capabilityRule returns [ParseNode *tree]
	@init {
		$tree = NULL;
		Comment *newComment;
	}
	: 'capability' { newComment = new_comment_node(NULL); }
	( incomingCapNode=capabilitiesSubExpr
	  {
	  	if ($tree == NULL)
		{
			$tree = $incomingCapNode.node;
			AttachCommentBlock($tree);
			$tree->pEOLComment = newComment;
		}
		else
		{
			add_parse_node_sibling($tree, $incomingCapNode.node);
		}
	})+ ','
	( endOfLineComment[newComment] )?
	;

/* Helper rule for 'capabilityRule' */
capabilitiesSubExpr returns [ParseNode *node]
	@init {
		ParseNode *capabilityNode = new_parse_node(ELEMENT_CAPABILITY,
								mpTree);
		THROW_IF_NULL(capabilityNode,rulecapabilitiesSubExprEx);
		Capability *capability = new_capability_node();
		THROW_IF_NULL(capability,rulecapabilitiesSubExprEx);
		capabilityNode->pData = capability;
		$node = capabilityNode;
	}
	:
	(capIdent=IDENT | capIdent=QUOTED_STRING)
	{
		capability->pCapability = strdup((char *) $capIdent.text->chars);
	}
	;

/* Relevant syntax:
	audit {
		/path/to/something rw,
	}

   This doesn't get wrapped in with the 'profileExpr' rule because only
   a subset of that grammar is supported, and it's just easier to write it
   out here.
*/
auditRule returns [ParseNode *tree]
	@init {
		Group *auditBlock;
		auditBlock = new_group_node(ELEMENT_GROUP_AUDIT);
		THROW_IF_NULL(auditBlock,ruleauditRuleEx);
		$tree = new_parse_node(ELEMENT_GROUP, mpTree);
		THROW_IF_NULL($tree,ruleauditRuleEx);
		$tree->pData = auditBlock;
		
		Comment *newComment = new_comment_node(NULL);
		AttachCommentBlock($tree);
		$tree->pEOLComment = newComment;
	}
	: 'audit' ( endOfLineComment[newComment] )? 
	LEFT_BRACE ( endOfLineComment[newComment] )?
	( incomingTree=accessRule
		{ add_parse_node_child($tree, $incomingTree.tree); }	
	)*
	RIGHT_BRACE ( endOfLineComment[newComment] )?
	;

		
/* Relevant syntax: if (@{var1})
 * 
 * Conditionals are a strange part of the parse tree, since they're both
 * "elements" and ParseNodes.  When a conditional is in the main parse tree,
 * the "if (blah)" element is all that is actually in the tree, with two 
 * ParseNode pointers: one to the list of rules within the if block,
 * and one to the else branch.  The else branch is also a Conditional element,
 * in order to attach block comments to it rather than to the first rule
 * in the else block.
 *
 * The tutorial should have a graphic to make this a little easier to 
 * understand.
 *
*/
conditionalIfExpr returns [ParseNode *tree]
	@init
	{
		Conditional *ifConditional = new_conditional_node();
		THROW_IF_NULL(ifConditional,ruleconditionalIfExprEx);
		$tree = new_parse_node(ELEMENT_CONDITIONAL, mpTree);
		THROW_IF_NULL($tree,ruleconditionalIfExprEx);
		$tree->pData = ifConditional;
		AttachCommentBlock($tree);
		
		Comment *newComment = new_comment_node(NULL);
		$tree->pEOLComment = newComment;
	}
	: 'if' LEFT_PAREN condExpr=ifExpr RIGHT_PAREN
		{ 
			ifConditional->pExpr = $condExpr.expr;
			ifConditional->pConditionalString =
					strdup((char *)$condExpr.string->chars);
		}
	 ( endOfLineComment[newComment] )?
	LEFT_BRACE ( endOfLineComment[newComment] )?
	ifTree=conditionalRules
	{
		ifConditional->pIfBranch = $ifTree.tree;
	}
	RIGHT_BRACE ( endOfLineComment[newComment] )?
	;

conditionalElseExpr returns [ParseNode *tree]
	@init {
		Conditional *elseConditional;
		elseConditional = new_conditional_node();
		THROW_IF_NULL(elseConditional,ruleconditionalElseExprEx);
		
		$tree = new_parse_node(ELEMENT_CONDITIONAL_ELSE, mpTree);
		THROW_IF_NULL($tree,ruleconditionalElseExprEx);
		$tree->pData = elseConditional;
		
		Comment *newComment = new_comment_node(NULL);
		THROW_IF_NULL(newComment,ruleconditionalElseExprEx);
		$tree->pEOLComment = newComment;
		AttachCommentBlock($tree);
	}
	: 'else' ( endOfLineComment[newComment] )? LEFT_BRACE
	( endOfLineComment[newComment] )?
	elseRules=conditionalRules
	{ 
		if ($elseRules.tree != NULL)
		add_parse_node_child($tree, $elseRules.tree);
	}
	RIGHT_BRACE ( endOfLineComment[newComment] )?
	;

conditionalRules returns [ParseNode *tree]
	@init {
		$tree = NULL;
	}
	:
	( newlineRule
	| startOfLineComment
	| ( incomingTree=accessRule
	  | incomingTree=capabilityRule
	  | incomingTree=auditRule
	  | incomingTree=builtInFunctions )
	  {
	  	if ($tree == NULL)
			$tree = $incomingTree.tree;
		else
			add_parse_node_sibling($tree, $incomingTree.tree);
	  }
	)*
	;

builtInFunctions returns [ParseNode *tree]
	@init {
		Function *newFunction = new_function_node();
		THROW_IF_NULL(newFunction,rulebuiltInFunctionsEx);

		$tree = new_parse_node(ELEMENT_FUNCTION, mpTree);
		THROW_IF_NULL($tree,rulebuiltInFunctionsEx);
		$tree->pData = newFunction;

		Comment *newComment = new_comment_node(NULL);
		THROW_IF_NULL(newComment,rulebuiltInFunctionsEx);

		$tree->pEOLComment = newComment;
		AttachCommentBlock($tree);
	}
	:
	( 'error' LEFT_PAREN funcData=QUOTED_STRING RIGHT_PAREN
		{ newFunction->mFunctionType = ELEMENT_FUNCTION_ERROR; }
	| 'undef' LEFT_PAREN LIST_VAR_START funcData=IDENT RIGHT_BRACE RIGHT_PAREN
		{ newFunction->mFunctionType = ELEMENT_FUNCTION_UNDEF; }
	| 'warn' LEFT_PAREN funcData =QUOTED_STRING RIGHT_PAREN
		{ newFunction->mFunctionType = ELEMENT_FUNCTION_WARN; }
	)
	{  newFunction->pFunctionInput = strdup((char *) $funcData.text->chars); }
	( endOfLineComment[newComment] )?
	;

ifExpr returns [ConditionalExpr *expr, pANTLR3_STRING string]
	@init {
		ConditionalExpr *nextLink = NULL;
		$expr = NULL;
		$string = NULL;
		int negated = 0;
		$string = factory->newRaw(factory);    

	}
	: ( n='not' 
	{
		negated = 1;
	}
	)?
	mainExpr=variableOrFunction
	{
		$string->append($string, " ");
		$string->appendS($string, $mainExpr.string);
		$mainExpr.expr->mNegated = negated;
		$expr = $mainExpr.expr;
	}
	( andExpr=andNotExpr
	{

		$string->append($string, " ");
		$string->appendS($string, $andExpr.string);		
		if (nextLink == NULL)
		{
			$andExpr.expr->pBack = $expr;
			$expr->pNext = $andExpr.expr;
			nextLink = $andExpr.expr;
		}
		else
		{
			nextLink->pNext = $andExpr.expr;
			$andExpr.expr->pBack = nextLink;
			nextLink = $andExpr.expr;
		}
	}
	)*
	;

variableOrFunction returns [ConditionalExpr *expr, pANTLR3_STRING string]
	@init {
		$string = factory->newRaw(factory);
		$expr = new_conditional_expr_node();
	}
	:
	(
	BOOL_VAR_START in=IDENT RIGHT_BRACE
	{ 
		$string->append($string, "${");
		$string->appendS($string, $in.text);
		$string->append($string, "} ");
		$expr->mCondType = ELEMENT_CONDITIONAL_EXPRESSION_BOOLEAN;
	}
	| 'exists' LEFT_PAREN (in=QUOTED_STRING|in=UNQUOTED_PATH) RIGHT_PAREN
	{
		$string->append($string, "exists(");
		$string->appendS($string, $in.text);
		$string->append($string, ") ");
		$expr->mCondType=ELEMENT_CONDITIONAL_EXPRESSION_EXISTS;
	}
	)
	{
		$expr->pExprVariable = strdup((char *) $in.text->chars); 
	}
	| 'defined' LEFT_PAREN
	{
		$string->append($string, "defined(");
	}
		( LIST_VAR_START definedVar=IDENT
		{
			$string->append($string, "@{");
			$string->appendS($string, $definedVar.text);
			$string->append($string, "}) ");
			$expr->mCondType = ELEMENT_CONDITIONAL_EXPRESSION_DEFINED_LIST;
		}
		| BOOL_VAR_START definedVar=IDENT
		{
			$string->append($string, "${");
			$string->append($string, "}) ");
			$expr->mCondType = ELEMENT_CONDITIONAL_EXPRESSION_DEFINED_BOOL;
		}
		)
		RIGHT_BRACE RIGHT_PAREN
		{ $expr->pExprVariable = strdup((char *) $definedVar.text->chars); }
	;

andNotExpr returns [ConditionalExpr *expr, pANTLR3_STRING string]
	@init {
		$string = factory->newRaw(factory);
		$expr = NULL;
		int negated = 0;
	}
	:
	( a='and' ('not' { negated = 1; } )? inExpr=variableOrFunction
	{
		$inExpr.expr->mLinkType=ELEMENT_CONDITIONAL_EXPRESSION_LINK_AND;
		$inExpr.expr->mNegated = negated;
	}
	| a='or' ('not' { negated = 1; } )? inExpr=variableOrFunction
	{
		$inExpr.expr->mLinkType =ELEMENT_CONDITIONAL_EXPRESSION_LINK_OR;
		$inExpr.expr->mNegated = negated;
	}
	)
	{ 	
		$string->appendS($string, $a.text);
		if (negated == 1)
			$string->append($string, " not");

		$string->append($string, " ");
		$string->appendS($string, $inExpr.string);
		$expr = $inExpr.expr;
	}
	;

/* Network syntax rules.
*/
networkRule returns [ParseNode *tree]
	@init {
		Network *networkNode = new_network_node();
		THROW_IF_NULL(networkNode,rulenetworkRuleEx);
		$tree = new_parse_node(ELEMENT_NETWORK, mpTree);
		THROW_IF_NULL($tree,rulenetworkRuleEx);
		Comment *newComment = new_comment_node(NULL);
		$tree->pData = networkNode;
		$tree->pEOLComment = newComment;
		AttachCommentBlock($tree);
	}
	: 'network'
	/* domain, type, and protocol are all that AA 2.1 supports.
	 * The remaining rules are around for the eventual day that they may be 
	 * used.
	 */
	( domain=domainRule
	{
		if ($domain.domain != NULL)
			networkNode->pDomain = strdup($domain.domain);
	}
	)?
	( type=typeRule
	{
		if ($type.type != NULL)
			networkNode->pType = strdup($type.type);
	}
	)?
	( protocol=protocolRule
	{
		if ($protocol.protocol != NULL)
			networkNode->pProtocol = strdup($protocol.protocol);
	}
	)?
	( action=networkActionRule
	{
		if ($action.tcp != NULL)
			networkNode->pAction1 = strdup($action.tcp);
		if ($action.udp1 != NULL)
			networkNode->pAction1 = strdup($action.udp1);
		if ($action.udp2 != NULL)
			networkNode->pAction2 = strdup($action.udp2);
	}
	)?
	( network=networkHostRule 
	{
		if ($network.direction != NULL)
			networkNode->pDirection1 = strdup($network.direction);
		if ($network.iprule != NULL)
			networkNode->pIPExpr1 = strdup($network.iprule);
	}
	 ( network2=networkHostRule
	 {
	 	if ($network2.direction != NULL)
			networkNode->pDirection2 = strdup($network2.direction);
		if ($network2.iprule != NULL)
			networkNode->pIPExpr2 = strdup($network2.iprule);
	 }
	 )? 
	)?
	( iface=ifaceRule
	{
		if ($iface.iface != NULL)
			networkNode->pIface = strdup($iface.iface);
	}
	)? 
	( limit=limitRule
	{
		if ($limit.limit != NULL)
			networkNode->pLimit = strdup($limit.limit);
	}
	)?
	( 'conntrack' { networkNode->mConntrack = 1; } )? ','
	( endOfLineComment[newComment] )?
	;

/* TODO: There are conflicts that should be resolvable with some tweaking 
   of the networkRule grammar.
*/ 
domainRule returns [char *domain]
	@init { $domain = NULL; }
	: 
	( d='inet'
	| d='ax25'
/*	| d='ipx' - This conflicts with protocolRule */
/*	| d='appletalk' - This conflicts with protocolRule */
	| d='netrom'
	| d='bridge'
	| d='atmpvc'
	| d='x25'
	| d='inet6'
	| d='rose'
	| d='netbeui'
	| d='security'
	| d='key'
	| d='packet'
        | d='ash'
	| d='econet'
	| d='atmsvc'
	| d='sna'
	| d='irda'
	| d='pppox'
	| d='wanpipe'
        | d='bluetooth')
	{ $domain = (char *) $d.text->chars; }
	;

typeRule returns [char *type]
	@init { $type = NULL; }
	:
	( t='stream'
	| t='dgram'
	| t='seqpacket'
	| t='rdm'
	| t='raw'
/*	| t='packet' - This conflicts with domainRule */
	)
	{ $type = (char *) $t.text->chars; }
	;

protocolRule returns [char *protocol]
	@init { $protocol = NULL; }
	: 
	( p='tcp'
	| p='udp'
	| p='ipx'
	| p='appletalk'
	| p='sctp'
	)
	{ $protocol = (char *) $p.text->chars; }
	;

networkActionRule returns [char *tcp, char *udp1, char *udp2]
	@init { $tcp = NULL; $udp1 = NULL; $udp2 = NULL; }
	: ( t=tcpRule { $tcp = $t.tcp; }
	  | u=udpRule { $udp1 = $u.udp; } 
	    ('&' u=udpRule { $udp2 = $u.udp; } )?
	  )
	  ;

tcpRule returns [char *tcp]
	@init { $tcp = NULL; }
	:
	( t='connect'
	| t='accept'
	| t='connected')
	{ $tcp = (char *) $t.text->chars; }
	;
	
udpRule returns [char *udp]
	@init { $udp = NULL; }
	:
	( u='send'
	| u='recv')
	{ $udp = (char *) $u.text->chars; }
	;
	
networkHostRule returns [char *direction, char *iprule]
	@init { $direction = NULL; $iprule = NULL; }
	:
	( d='to'
	| d='from'
	| d='endpoint' )
	i=ipRule
	{ $direction = (char *) $d.text->chars; $iprule = $i.iprule; }
	;

/* TODO: For now, IP addresses will come in as IDENT tokens entirely.
   This is not optimal.
*/

ipRule returns [char *iprule]
	@init { $iprule = NULL; }
	: i=IDENT { $iprule = (char *) $i.text->chars; }
	;


ifaceRule returns [char *iface]
	@init { $iface = NULL; }
	: 'via' i=IDENT { $iface = (char *) $i.text->chars; }
	;

limitRule returns [char *limit]
	@init { $limit = NULL; }
	: 'limit' i=IDENT { $limit = (char *) $i.text->chars; }
	;

/* Lexer section */

/* We need to track newlines because of the way variable assignments work.
   There is a full explanation up near the 'newlineRule' part of the parser.
*/

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
LESS_THAN	: { startOfLine = 1; }	'<' ;
GREATER_THAN	: { startOfLine = 1; }	'>' ;
LEFT_BRACE	: { startOfLine = 1; }	'{' ;
RIGHT_BRACE	: { startOfLine = 1; }	'}' ;
AT		: { startOfLine = 1; }	'@' ;
DOLLAR		: { startOfLine = 1; }	'$' ;
LEFT_PAREN	: { startOfLine = 1; }	'(' ;
RIGHT_PAREN	: { startOfLine = 1; }	')' ;
PLUS		: '+' ;
EQUALS		: { equalSign = 1; } '=' ;

/* Disambiguate the #include from the #comments */
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

INCLUDE
	: 'include'
		{ $type=INCLUDE; inInclude = 1;}
	;

/* For some reason, ANTLR 3 doesn't like imaginary tokens
   (although all of the docs say it does.  So define these two
   fragments to prevent hassle.
*/
fragment
SOL_COMMENT : '#' COMMENT
	;

fragment
EOL_COMMENT : '#' COMMENT
	;


/* This rule will eat up anything after a # */

fragment
COMMENT
	: (~('\n'|'\r'))*
	;

fragment
ANYTHING_NOT_QUOTED
	: (~'"')*// "
	;
	
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

fragment
PATH 
	: '/' ('a'..'z'|'A'..'Z'|'_'|'*'| '[' | ']'
		|'0'..'9'|'-'|'.'|'/'|'\u0080'..'\u00ff')*
		{ startOfLine = 1; }
	;

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

LIST_VAR_START 
	: '@' '{'
	{ startOfLine = 1; inVariable = 1; }
	;
	
BOOL_VAR_START
	: '$' '{'
	{ startOfLine = 1; inVariable = 1; }
	;

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
	
fragment 
IDENT_START
	: 'a'..'z'
	|'A'..'Z'
	|'_'
	|'0'..'9'
	|'\u0080'..'\u00ff'
	;

fragment
IDENT_CONTINUE
	:  IDENT_START
	| '*'
	|'.'
	|'-'
	|':'
	|'/'
	;

fragment
REAL_IDENT
	: IDENT_START ( IDENT_CONTINUE )*
	;
IDENT
	: f=REAL_IDENT
	{
		if (inInclude == 1)
			lexerIncludeFile=strdup((char *) $f.text->chars);
		startOfLine = 1;
		$type = IDENT; 
	}
 	;


WS:	(' '|'\t')+ { $channel = HIDDEN; };
