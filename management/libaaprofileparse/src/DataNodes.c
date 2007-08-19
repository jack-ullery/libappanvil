#define _GNU_SOURCE
#include <stdio.h>

#include "DataNodes.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libaaprofileparse.h"

ParseError *new_parse_error(void)
{
	ParseError *retError = (ParseError *) malloc(sizeof(ParseError));
	if (retError != NULL)
	{
		retError->mLine = 0;
		retError->mPos = 0;
		retError->mErrorType = ERROR_UNKNOWN;
		retError->pName = NULL;
		retError->pMessage = NULL;
	}
	return retError;
}

void free_parse_error(ParseError *error)
{
	if (error == NULL) return;

	if (error->pName != NULL)
		free(error->pName);

	if (error->pMessage != NULL)
		free(error->pMessage);

	free(error);
}

Capability *new_capability_node(void)
{
	Capability *retCapability = (Capability *) malloc(sizeof(Capability));
	if (retCapability != NULL)
	{
		retCapability->pCapability = NULL;
	}

	return retCapability;
}
char *capability_node_to_string(Capability *capability)
{
	char *retChar;
	asprintf(&retChar, "capability %s,", capability->pCapability);
	return retChar;
}

void free_capability_node(Capability *node)
{
	if (node == NULL) return;

	if (node->pCapability != NULL)
		free(node->pCapability);

	if (node != NULL)
		free(node);
}
Comment *new_comment_node(char *comment)
{
	Comment *retComment = (Comment *) malloc(sizeof(Comment));
	if (retComment != NULL)
	{
		retComment->pCommentText = NULL;

		if (comment != NULL)
			retComment->pCommentText = strdup(comment);
	}

	return retComment;
}

void free_comment_node(Comment *node)
{
	if (node == NULL) return;

	if (node->pCommentText != NULL)
		free(node->pCommentText);
	if (node != NULL)
		free(node);
}

char *comment_node_to_string(Comment *node)
{
	char *retChar;
	asprintf(&retChar, "%s", node->pCommentText);
	return retChar;
}

ChangeProfile *new_change_profile_node(void)
{
	ChangeProfile *retChangeProfile = (ChangeProfile *) malloc(sizeof(ChangeProfile));
	if (retChangeProfile != NULL)
	{
		retChangeProfile->pProfile = NULL;
	}
	return retChangeProfile;
}

char *change_profile_to_string(ChangeProfile *node)
{
	char *retChar;
	asprintf(&retChar,"change_profile %s ,", node->pProfile);
	return retChar;
}

void free_change_profile_node(ChangeProfile *node)
{
	if (node == NULL) return;

	if (node->pProfile != NULL)
		free(node->pProfile);
	if (node != NULL);
		free(node);
}

Conditional *new_conditional_node(void)
{
	Conditional *expr = (Conditional *) malloc(sizeof(Conditional));
	if (expr != NULL)
	{
		expr->pExpr = NULL;
		expr->pConditionalString = NULL;
		expr->pIfBranch = NULL;
		expr->pElseBranch = NULL;
	}
	return expr;
}

ParseNode *evaluate_conditional(Conditional *node, VariableList *list)
{
	if (node == NULL) return NULL;

	ConditionalExpr *tmpExpr;
	ParseNode *retNode = node->pIfBranch;
	int exprEval;

	/* Walk down the ConditionalExpr list and evaluate each expression
	 * in turn */
	tmpExpr = node->pExpr;
	while (tmpExpr != NULL)
	{
		exprEval = evaluate_conditional_expr(tmpExpr, list);
		if (tmpExpr->mNegated == 1)
		{
			/* If the value is false, and it's negated,
			 * it should evaluate as true
			 */
			if (exprEval == 0)
				exprEval = 1;
			/* Otherwise, if value is true, and it's negated,
			 * we should evaluate as false.
			 */
			else 
				exprEval = 0;
		}
		if ((exprEval != 1) /* The variable does not evaluate to TRUE */
		    && (tmpExpr->mLinkType != ELEMENT_CONDITIONAL_EXPRESSION_LINK_OR))
		{
			/* This expression has failed entirely, which means we don't need to
			 * look any further.
			 */
			retNode = node->pElseBranch;
			break;
		}

		tmpExpr = tmpExpr->pNext;
	}

	return retNode;
}
int evaluate_conditional_expr(ConditionalExpr *expr, VariableList *list)
{
	VariableList *resultList;
	int returnValue = 0;
	if ((expr == NULL) || (list == NULL)) return 0;

	/* Take care of the two boolean-specific evaluations */
	if ((expr->mCondType == ELEMENT_CONDITIONAL_EXPRESSION_DEFINED_BOOL)
		|| (expr->mCondType == ELEMENT_CONDITIONAL_EXPRESSION_BOOLEAN))
	{
		resultList = find_variable_list_by_name(list,
							expr->pExprVariable);
		if (resultList != NULL)
		{
			if (expr->mCondType == ELEMENT_CONDITIONAL_EXPRESSION_DEFINED_BOOL)
			{
				/* All we need to do is verify that it actually exists, and is a boolean */
				returnValue = resultList->pFirstEntry->mIsBoolValue;
			}
			else
			{
				/* if( ${bool} ) will evaluate to TRUE if the value is TRUE */
				if (resultList->pFirstEntry->mIsBoolValue == 1)
				{
					returnValue = resultList->pFirstEntry->mValues.mBoolValue;
				}
			}
		}
	}
	/* Verify that the variable actually exists - doesn't matter what the value is */
	else if (expr->mCondType == ELEMENT_CONDITIONAL_EXPRESSION_DEFINED_LIST)
	{
		resultList = find_variable_list_by_name(list, expr->pExprVariable);
		if (resultList != NULL)
		{
			if (resultList->pFirstEntry->mIsBoolValue == 0)
				returnValue = 1;
		}
	}
	/* Check whether or not a file exists. */
	else if (expr->mCondType == ELEMENT_CONDITIONAL_EXPRESSION_EXISTS)
	{
		if (access(expr->pExprVariable, F_OK) == 0)
			returnValue = 1;
	}
	return returnValue;
}

void free_conditional_node(Conditional *node)
{
	if (node == NULL) return;

	if (node->pExpr != NULL)
		free_conditional_expr_node(node->pExpr);

	if (node->pConditionalString != NULL)
		free(node->pConditionalString);

	if (node->pIfBranch != NULL)
		cleanup_parse_tree(node->pIfBranch);

	if (node->pElseBranch != NULL)
		cleanup_parse_tree(node->pElseBranch);

	if (node != NULL)
		free(node);
}

char *conditional_node_to_string(Conditional *node)
{
	/* TODO */
	return NULL;
}

ConditionalExpr *new_conditional_expr_node(void)
{
	ConditionalExpr *retExpr = (ConditionalExpr *) malloc(sizeof(ConditionalExpr));
	if (retExpr != NULL)
	{
		retExpr->mCondType = ELEMENT_CONDITIONAL_EXPRESSION_INVALID;
		retExpr->mLinkType = ELEMENT_CONDITIONAL_EXPRESSION_LINK_INVALID;
		retExpr->mNegated = 0;
		retExpr->pExprVariable = NULL;
		retExpr->pBack = NULL;
		retExpr->pNext = NULL;
	}

	return retExpr;
}

char *conditional_expr_to_string(ConditionalExpr *node)
{
	/* TODO */
	return NULL;
}

void free_conditional_expr_node(ConditionalExpr *node)
{
	if (node == NULL) return;

	if (node->pNext != NULL)
		free_conditional_expr_node(node->pNext);

	if (node->pExprVariable != NULL)
		free(node->pExprVariable);
	if (node != NULL)
		free(node);
}

File *new_file_node(void)
{
	File *retFile = (File *) malloc(sizeof(File));
	if (retFile != NULL)
	{
		retFile->pFilePath = NULL;
		retFile->pFileName = NULL;
	}

	return retFile;
}

void free_file_node(File *node)
{
	if (node == NULL) return;

	if (node->pFilePath != NULL)
		free(node->pFilePath);
	if (node->pFileName != NULL)
		free(node->pFileName);
	if (node != NULL)
		free(node);
}

Function *new_function_node(void)
{
	Function *retFunction = (Function *) malloc(sizeof(Function));
	if (retFunction != NULL)
	{
		retFunction->mFunctionType = ELEMENT_FUNCTION_INVALID;
		retFunction->pFunctionInput = NULL;
	}

	return retFunction;
}
void free_function_node(Function *node)
{
	if (node == NULL) return;

	if (node->pFunctionInput != NULL)
		free(node->pFunctionInput);
	if (node != NULL)
		free(node);
}

char *function_node_to_string(Function *node)
{
	char *retChar;
	if (node->mFunctionType == ELEMENT_FUNCTION_WARN)
		asprintf(&retChar, "warn(%s)", node->pFunctionInput);
	else if (node->mFunctionType == ELEMENT_FUNCTION_ERROR)
		asprintf(&retChar, "error(%s)", node->pFunctionInput);
	else if (node->mFunctionType == ELEMENT_FUNCTION_UNDEF)
		asprintf(&retChar,"undef(%s)", node->pFunctionInput);
	else
		retChar = NULL;

	return retChar;
}

Group *new_group_node(GroupType type)
{
	Group *retGroup = (Group *) malloc(sizeof(Group));
	if (retGroup != NULL)
	{
		retGroup->mGroupType = type;
		retGroup->pIdentifier = NULL;
		retGroup->mFlags = 0;
	}

	return retGroup;
}

void free_group_node(Group *node)
{
	if (node == NULL) return;

	if (node->pIdentifier != NULL)
		free(node->pIdentifier);
	if (node != NULL)
		free(node);
}

char *group_node_to_string(Group *node)
{
	/* TODO */
	return NULL;
}

Include *new_include_node(void)
{
	Include *retInclude = (Include *) malloc(sizeof(Include));
	if (retInclude != NULL)
	{
		retInclude->pIncludeFile = NULL;
	}

	return retInclude;
}

void free_include_node(Include *node)
{
	if (node == NULL) return;

	if (node->pIncludeFile != NULL)
		free(node->pIncludeFile);
	if (node != NULL)
		free(node);
}

char *include_node_to_string(Include *node)
{
	char *retChar;
	asprintf(&retChar, "#include <%s>", node->pIncludeFile);
	return retChar;
}

Network *new_network_node(void)
{
	Network *retNet = (Network *) malloc(sizeof(Network));
	if (retNet != NULL)
	{
		retNet->mConntrack = 0;
		retNet->pDomain = NULL;
		retNet->pType = NULL;
		retNet->pProtocol = NULL;
		retNet->pAction1 = NULL;
		retNet->pAction2 = NULL;
		retNet->pDirection1 = NULL;
		retNet->pDirection2 = NULL;
		retNet->pIPExpr1 = NULL;
		retNet->pIPExpr2 = NULL;
		retNet->pIface = NULL;
		retNet->pLimit = NULL;
	}

	return retNet;
}

void free_network_node(Network *node)
{
	if (node == NULL) return;

	if (node->pDomain != NULL)
		free(node->pDomain);
	if (node->pType != NULL)
		free(node->pType);
	if (node->pProtocol != NULL)
		free(node->pProtocol);
	if (node->pAction1 != NULL)
		free(node->pAction1);
	if (node->pAction2 != NULL)
		free(node->pAction2);
	if (node->pDirection1 != NULL)
		free(node->pDirection1);
	if (node->pDirection2 != NULL)
		free(node->pDirection2);
	if (node->pIPExpr1 != NULL)
		free(node->pIPExpr1);
	if (node->pIPExpr2 != NULL)
		free(node->pIPExpr2);
	if (node->pIface != NULL)
		free(node->pIface);
	if (node->pLimit != NULL)
		free(node->pLimit);
	if (node != NULL)
		free(node);
}
char *network_node_to_string(Network *node)
{
	/* TODO */
	return NULL;
}

Option *new_option_node(void)
{
	Option *retOption = (Option *) malloc(sizeof(Option));
	if (retOption != NULL)
	{
		retOption->mOptionType = OPTION_INVALID;
	}

	return retOption;
}

extern char *option_node_to_string(Option *node)
{
	/* TODO */
	return NULL;
}


void free_option_node(Option *node)
{
	if (node == NULL) return;

	if ((node->mOptionType == OPTION_VERSION) || (node->mOptionType == OPTION_ENCODING))
	{
		if (node->mValue.pCharValue != NULL)
			free(node->mValue.pCharValue);
	}
	if (node != NULL)
		free(node);
}


Rule *new_rule_node(void)
{
	Rule *retRule = (Rule *) malloc(sizeof(Rule));
	if (retRule != NULL)
	{
		retRule->pResource = NULL;
		retRule->pExpandedResource = NULL;
		retRule->mPerms = 0;
	}

	return retRule;
}


void free_rule_node(Rule *node)
{
	if (node == NULL) return;

	if (node->pResource != NULL)
		free(node->pResource);
	if (node->pExpandedResource != NULL)
		free(node->pExpandedResource);
	if (node->pPermString != NULL)
		free(node->pPermString);
	if (node != NULL)
		free(node);
}

char *rule_node_to_string(Rule *node)
{
	char *retChar;
	return asprintf(&retChar,"%s %s ,",
			node->pResource,
			node->pPermString);
	return retChar;
}

VariableAssignment *new_variable_assignment_node(void)
{
	VariableAssignment *retAssign = (VariableAssignment *) malloc(sizeof(VariableAssignment));
	if (retAssign != NULL)
	{
		retAssign->mIsBoolValue = 0;
		retAssign->mPlusEquals = 0;
		retAssign->pName = NULL;
		retAssign->pValue = NULL;
	}

	return retAssign;
}


void free_variable_assignment_node(VariableAssignment *node)
{
	if (node == NULL) return;

	if (node->pName != NULL)
		free(node->pName);
	if (node->pValue != NULL)
		free(node->pValue);
	if (node != NULL)
		free(node);
}

char *variable_assignment_node_to_string(VariableAssignment *node)
{
	/* TODO */
	return NULL;
}

struct _VariableList *new_variable_list(void)
{
	VariableList *retList = (VariableList *) malloc(sizeof(VariableList));
	if (retList != NULL)
	{
		retList->pName = NULL;
		retList->pFirstEntry = NULL;
		retList->pBack = NULL;
		retList->pNext = NULL;
	}
	return retList;
}

/* TODO: This is muddled and needs to be redone */
void add_variable_list_entry(VariableList *list, VariableListEntry *entry)
{
	VariableList *tmpList;
	if ((list== NULL) || (entry == NULL))
		return;

	if (list->pName == NULL) /* It's a fresh root node, reuse it */
	{
		list->pName = strdup(entry->pName);
		list->pFirstEntry = entry;
		return;
	}
	/* Do we match the node that we are currently on? */
	if (strcmp(list->pName, entry->pName) == 0)
	{
		/* There are no values attached, but it has a name? */
		if (list->pFirstEntry == NULL)
		{
			if (list->pName != NULL)
				free(list->pName);
			list->pName = strdup(entry->pName);
			list->pFirstEntry = entry;
		}
		else
		{
			/* If we're trying to add an entry to a boolean value, 
			 * clear out the other entries first.
			 */
			if (list->pFirstEntry->mIsBoolValue == 0)
			{
				variable_list_entry_add_sibling(list->pFirstEntry, entry);
			}
			else
			{
				free_variable_list_entries(list->pFirstEntry);
				list->pFirstEntry = entry;
			}
		}
	}
	else /* We don't match, so look ahead */
	{
		/* See if we can find a matching entry */
		tmpList = find_variable_list_by_name(list, entry->pName);
		/* There's a match, so add the value to it */
		if (tmpList != NULL)
		{
			add_variable_list_entry(tmpList, entry);
		}
		else
		{
			/* No match, so make a new Variable List node, attach the
			 * entry to it, and then attache the node to this one.
			 */
			tmpList = new_variable_list();
			tmpList->pName = strdup(entry->pName);
			tmpList->pFirstEntry = entry;
			tmpList->pBack = list;
			tmpList->pNext = list->pNext;

			if (list->pNext != NULL)
				list->pNext->pBack = tmpList;

			list->pNext = tmpList;
			
		}
	}
}

void append_variable_list_values(VariableList *list, char *name, char *append_name)
{
	if ((list == NULL) || (name == NULL) || (append_name == NULL))
		return;

	VariableList *appendList;
	VariableListEntry *appendEntry, *tmpEntry;

	appendList = find_variable_list_by_name(list, append_name);

	if (appendList == NULL)
		return;

	tmpEntry = appendList->pFirstEntry;
	while (tmpEntry != NULL)
	{
		appendEntry = new_variable_list_entry();
		appendEntry->pName = strdup(name);
		appendEntry->mValues.pValue = strdup(tmpEntry->mValues.pValue);
		add_variable_list_entry(list, appendEntry);
		tmpEntry = tmpEntry->pNext;
	}
}
VariableList *find_variable_list_by_name(VariableList *list, char *name)
{
	if ((list == NULL) || (name == NULL)) return NULL;

	if (list->pName == NULL) return NULL;

	if (strcmp(list->pName, name) == 0)
	{
		return list;
	}
	else
	{
		return find_variable_list_by_name(list->pNext, name);
	}
}

/* Removes a VariableList (and it's associated VariableListEntries)
 * from the chain.
 */
VariableList *del_variable_list_by_name(VariableList *rootList, char *name)
{
	VariableList *retList;
	if ((rootList == NULL) || (name == NULL)) return rootList;

	/* It must be a freshly created root node, so don't do anything */
	if ((rootList->pName == NULL) && (rootList->pFirstEntry == NULL))
		return rootList;

	VariableList *tmp = find_variable_list_by_name(rootList, name);
	if (tmp != NULL)
	{
		if (tmp->pBack != NULL)
		{
			tmp->pBack->pNext = tmp->pNext;
			retList = rootList;
		}
		else
		{
			retList = tmp->pNext;
		}

		if (tmp->pNext != NULL)
			tmp->pNext->pBack = tmp->pBack;
		
		del_variable_list(tmp);
	}
	else
	{
		retList = rootList;
	}
		return retList;

}

void del_variable_list(VariableList *list)
{
	if (list == NULL) return;

	if (list->pName != NULL)
		free(list->pName);
	if (list->pFirstEntry != NULL)
		free_variable_list_entries(list->pFirstEntry);

	free(list);
}

void free_entire_variable_list(VariableList *list)
{
	if (list == NULL) return;

	if (list->pNext != NULL)
		free_entire_variable_list(list->pNext);

	if (list->pName != NULL)
		free(list->pName);
	if (list->pFirstEntry != NULL)
		free_variable_list_entries(list->pFirstEntry);

	free(list);
}

struct _VariableListEntry *new_variable_list_entry(void)
{
	VariableListEntry *retEntry = (VariableListEntry *) malloc(sizeof(VariableListEntry));
	if (retEntry != NULL)
	{
		retEntry->mIsBoolValue = 0;
		retEntry->pName = NULL;
		retEntry->mValues.pValue = NULL;
		retEntry->pNext = NULL;
		retEntry->pBack = NULL;
	}
	return retEntry;
}

void variable_list_entry_add_sibling(VariableListEntry *first, VariableListEntry *sibling)
{
	if ((first == NULL) || (sibling == NULL))
		return;

	if (first->pNext == NULL)
	{
		sibling->pBack = first;
		first->pNext = sibling;
	}
	else
	{
		variable_list_entry_add_sibling(first->pNext, sibling);
	}
}

void free_variable_list_entries(VariableListEntry *entry)
{
	if (entry == NULL) return;
	if (entry->pNext != NULL)
		free_variable_list_entries(entry->pNext);

	del_variable_list_entry(entry);
}

void del_variable_list_entry(VariableListEntry *entry)
{
	if (entry == NULL) return;

	if (entry->pName != NULL)
		free(entry->pName);

	if (entry->mIsBoolValue == 0)
	{
		if (entry->mValues.pValue != NULL)
			free(entry->mValues.pValue);
	}
	free(entry);
}

