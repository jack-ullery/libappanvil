#include "libaaprofileparse.h"
#include "AppArmorLexer.h"
#include "AppArmorParser.h"
#include "Exceptions.h"

ParseNode *parse_file (char *file)
{
	ParseNode *return_node = NULL;

	/* ANTLR3 prefers that we use their abstract types whenever possible */
	pANTLR3_UINT8 filename; 

	/* ANTLR uses input streams to feed data to the lexer.  The input stream
	 * can be taken from a memory string or a file.  We'll use a file here.
	 */
	pANTLR3_INPUT_STREAM input;

	/* The lexer and parser */
	pAppArmorLexer lexer;
	pAppArmorParser parser;

	/* The token stream, which is what the parser gets from the lexer. */
	pANTLR3_COMMON_TOKEN_STREAM token_stream;

 	filename = (pANTLR3_UINT8) file;

	/* Set up the input stream.  Another option, which could be useful for 
	 * parsing profile fragments, would be antlr3NewAsciiStringInPlaceStream()
	 */
	input = antlr3AsciiFileStreamNew(filename);

	/* Verify that the input stream was created properly */
	if ((ANTLR3_UINT64)input < 0)
	{
	/* TODO: develop an error reporting system that will work in a threaded
	 * environment.  Once that's in place, check to see if input == ANTLR3_ERR_NOMEM
	 */
		return NULL;
	}

	/* The input stream is fine, so create the lexer and hook the two together */
	lexer = AppArmorLexerNew(input);
	if ((ANTLR3_UINT64)lexer < 0)
	{
	/* Same as above, eventually check for ANTLR3_ERR_NOMEM */
		input->close(input);
		return NULL;
	}

	lexer->pLexer->rec->reportError = lexer_error_handler;

	/* Time for the token stream */
	token_stream = antlr3CommonTokenStreamSourceNew(ANTLR3_SIZE_HINT, lexer->pLexer->tokSource);
	if ((ANTLR3_UINT64)token_stream < 0)
	{
	/* You guessed it, eventually check for ANTLR3_ERR_NOMEM */
		lexer->free(lexer);
		input->close(input);
		return NULL;
	}

	/* The last part is setting the parser up to work with the token stream */
	parser = AppArmorParserNew(token_stream);
	if ((ANTLR3_UINT64)token_stream < 0)
	{
		token_stream->free(token_stream);
		lexer->free(lexer);
		input->close(input);
		return NULL;
	}

	/* One of the nice things about ANTLR is being able to call any parse action as a starting point.
	 * At some point it might be handy to open that ability up so applications can parse fragments of profiles.
	 * This function needs to start from the top, though.
	 */
	return_node = parser->startParse(parser);
	File *retFile = (File *) return_node->pData;
	retFile->pFileName = strdup(file);

	/* Free everything */
	parser->free(parser);
	token_stream->free(token_stream);
	lexer->free(lexer);
	input->close(input);
	return return_node;
}

void cleanup_parse_tree(ParseNode *tree)
{
	ParseNode *tmp;

	if (tree->pError != NULL)
	{
		free_parse_error(tree->pError);
		tree->pError = NULL;
	}

	if (tree->pVariableList != NULL)
	{
		free_entire_variable_list(tree->pVariableList);
		tree->pVariableList = NULL;
	}
	if (tree == NULL)
		return;

	if (tree->pChild != NULL)
	{
		ParseNode *childNode = tree->pChild;
		while (childNode != NULL)
		{
			tmp = childNode->pSibling;
			cleanup_parse_tree(childNode);
			childNode = tmp;
		}
	}
	free_comment_node(tree->pCommentBlock);
	free_comment_node(tree->pEOLComment);
	switch (tree->mNodeType)
	{
		case ELEMENT_COMMENT:
		{
			free_comment_node((Comment *) tree->pData);
			break;
		}
		case ELEMENT_RULE:
		{
			free_rule_node((Rule *) tree->pData);
			break;
		}
		case ELEMENT_FUNCTION:
		{
			free_function_node((Function *) tree->pData);
			break;
		}
		case ELEMENT_VARIABLE_ASSIGNMENT:
		{
			free_variable_assignment_node((VariableAssignment *) tree->pData);
			break;
		}
		case ELEMENT_OPTION:
		{
			free_option_node((Option *) tree->pData);
			break;
		}
		case ELEMENT_GROUP:
		{
			free_group_node((Group *) tree->pData);
			break;
		}
		case ELEMENT_FILE:
		{
			free_file_node((File *) tree->pData);
			break;
		}
		case ELEMENT_INCLUDE:
		{
			free_include_node((Include *) tree->pData);
			break;
		}
		case ELEMENT_CAPABILITY:
		{
			free_capability_node((Capability *) tree->pData);
			break;
		}
		case ELEMENT_CONDITIONAL:
		{
			free_conditional_node((Conditional *) tree->pData);
			break;
		}
		case ELEMENT_CONDITIONAL_ELSE:
		{
			free_conditional_node((Conditional *) tree->pData);
			break;
		}
		case ELEMENT_NETWORK:
		{
			free_network_node((Network *) tree->pData);
			break;
		}
		case ELEMENT_CHANGE_PROFILE:
		{
			free_change_profile_node((ChangeProfile *) tree->pData);
			break;
		}
		default:
		{
			break;
		}
	}
	free_parse_node(tree);
}