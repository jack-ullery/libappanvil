#include <stdio.h>
#include <stdlib.h>
#include "libaaprofileparse.h"

/*
 * This test program accepts a file path on the command line,
 * reads in a profile fragment from it, attempts to parse it,
 * and prints out the results from libaaprofileparse.
 *
 */

void print_node(ParseNode *node);

int main (int argc, char **argv)
{
	ParseNode *tree = NULL;
	if (argc != 2)
	{
		printf("Usage: test_multi.multi <filename>\n");
		exit(0);
	}

	printf("START\nFile: %s\n", argv[1]);
	tree = parse_file(argv[1]);
	if (tree != NULL)
	{
		if (tree->mError == 1)
		{
			printf("There was a parse error.\n");
			printf("Name: %s\n", tree->pError->pName);
			printf("Message: %s\n", tree->pError->pMessage);
			printf("Line / Position: %i / %i\n", tree->pError->mLine, tree->pError->mPos);
		}
		else
		{
			print_node(tree);
		}
		cleanup_parse_tree(tree);
	}

	printf("END\n");
	return(0);
}

void print_node(ParseNode *node)
{
	if (node == NULL)
	{
		printf("NULL NODE\n");
		return;
	}

	printf("Node type: ");
	switch (node->mNodeType)
	{
		case ELEMENT_COMMENT:
		{
			Comment *thisComment = (Comment *) node->pData;
			printf("COMMENT\n");
			printf("|-----Text: %s\n", thisComment->pCommentText);
			break;
		}
		case ELEMENT_RULE:
		{
			Rule *thisRule = (Rule *) node->pData;
			printf("RULE\n");
			printf("|-----Resource: %s\n", thisRule->pResource);
			printf("|-----Expanded resource: %s\n", thisRule->pExpandedResource);
			printf("|-----Mode: %s\n", thisRule->pPermString);
			break;
		}
		case ELEMENT_FUNCTION:
		{
			Function *thisFunction = (Function *) node->pData;
			printf("FUNCTION\n");
			printf("|-----Input: %s\n", thisFunction->pFunctionInput);
			printf("|-----Type: ");
			if (thisFunction->mFunctionType == ELEMENT_FUNCTION_WARN)
				printf("Warn\n");
			else if (thisFunction->mFunctionType == ELEMENT_FUNCTION_ERROR)
				printf("Error\n");
			else if (thisFunction->mFunctionType == ELEMENT_FUNCTION_UNDEF)
				printf("Undef\n");
			else if (thisFunction->mFunctionType == ELEMENT_FUNCTION_INVALID)
				printf("Invalid\n");
			break;
		}
		case ELEMENT_VARIABLE_ASSIGNMENT:
		{
			VariableAssignment *thisAssignment = (VariableAssignment *) node->pData;
			printf("VARIABLE ASSIGNMENT\n");
			printf("|-----Boolean: %s\n", (thisAssignment->mIsBoolValue == 1) ? "yes" : "no");
			printf("|-----Name: %s\n", thisAssignment->pName);
			printf("|-----Assignment: %s\n", (thisAssignment->mPlusEquals == 1) ? "+=" : "=");
			printf("|-----Value: %s\n", thisAssignment->pValue);
			VariableList *list = node->pRootNode->pVariableList;
			if (list != NULL)
			{
				printf("|-----Values from Variable List:\n");
				VariableList *varTmp = find_variable_list_by_name(list, thisAssignment->pName);
				if (varTmp != NULL)
				{
					VariableListEntry *vEntry = varTmp->pFirstEntry;
					while (vEntry != NULL)
					{
						if (vEntry->mIsBoolValue == 0)
							printf("|-----Value: %s\n", vEntry->mValues.pValue);
						else
							printf("|-----Value: %s\n", (vEntry->mValues.mBoolValue == 0) ? "false" : "true");
						vEntry = vEntry->pNext;
					}
				}
			}
			break;
		}
		case ELEMENT_OPTION:
		{
			Option *thisOption = (Option *) node->pData;
			printf("OPTION\n");
			if (thisOption->mOptionType == OPTION_VERSION)
			{
				printf("|-----Type: version\n");
				printf("|-----Value: %s\n", thisOption->mValue.pCharValue);
			}
			else if (thisOption->mOptionType == OPTION_ENCODING)
			{
				printf("|-----Type: encoding\n");
				printf("|-----Value: %s\n", thisOption->mValue.pCharValue);
			}
			else if (thisOption->mOptionType == OPTION_DISABLED)
			{
				printf("|-----Type: disabled\n");
				printf("|-----Value: %s\n", (thisOption->mValue.mBoolValue == 1) ? "yes" : "no");
			}
			else if (thisOption->mOptionType == OPTION_AUDIT)
			{
				printf("|-----Type: audit\n");
				printf("|-----Value: %s\n", (thisOption->mValue.mBoolValue == 1) ? "yes" : "no");
			}
			else if (thisOption->mOptionType == OPTION_COMPLAIN)
			{
				printf("|-----Type: complain\n");
				printf("|-----Value: %s\n", (thisOption->mValue.mBoolValue == 1) ? "yes" : "no");
			}
			else if (thisOption->mOptionType == OPTION_INVALID)
			{
				printf("|-----Type: invalid\n");
			}
			break;
		}
		case ELEMENT_GROUP:
		{
			Group *thisGroup = (Group *) node->pData;
			printf("GROUP\n");
			printf("|-----Identifier: %s\n", thisGroup->pIdentifier);
			if (thisGroup->mGroupType == ELEMENT_GROUP_AUDIT)
				printf("|-----Type: audit\n");
			else if (thisGroup->mGroupType == ELEMENT_GROUP_SUBPROFILE)
				printf("|-----Type: subprofile\n");
			else if (thisGroup->mGroupType == ELEMENT_GROUP_TRANSITION_PROFILE)
				printf("|-----Type: transition profile\n");
			else if (thisGroup->mGroupType == ELEMENT_GROUP_INVALID)
				printf("|-----Type: invalid\n");
			/* TODO: print the mode flags */
			break;
		}
		case ELEMENT_FILE:
		{
			File *thisFile = (File *) node->pData;
			printf("FILE\n");
			printf("|-----Path: %s\n", thisFile->pFilePath);
			printf("|-----Filename: %s\n", thisFile->pFileName);
			break;
		}
		case ELEMENT_INCLUDE:
		{
			Include *thisInclude = (Include *) node->pData;
			printf("INCLUDE\n");
			printf("|-----File: %s\n", thisInclude->pIncludeFile);
			break;
		}
		case ELEMENT_CAPABILITY:
		{
			Capability *thisCapability = (Capability *) node->pData;
			printf("CAPABILITY\n");
			printf("|-----Capability: %s\n",thisCapability->pCapability);
			break;
		}
		case ELEMENT_CONDITIONAL:
		{
			Conditional *thisCond = (Conditional *) node->pData;
			printf("CONDITIONAL\n");
			printf("Conditional string: %s\n", thisCond->pConditionalString);
			printf("If Branch:\n");
			print_node(thisCond->pIfBranch);
			printf("Else Branch:\n");
			print_node(thisCond->pElseBranch);
			printf("Evaluating conditional:\n");
			print_node(evaluate_conditional(thisCond, node->pRootNode->pVariableList));
			printf("All Done\n");
			break;
		}
		case ELEMENT_CONDITIONAL_ELSE:
		{
			printf("CONDITIONAL ELSE\n");
			break;
		}
		case ELEMENT_NETWORK:
		{
			Network *thisNetwork = (Network *) node->pData;
			printf("NETWORK\n");
			printf("|-----Conntrack: %s\n", (thisNetwork->mConntrack==1) ? "yes" : "no");
			printf("|-----Domain: %s\n", thisNetwork->pDomain);
			printf("|-----Type: %s\n", thisNetwork->pType);
			printf("|-----Protocol: %s\n", thisNetwork->pProtocol);
			printf("|-----Action1: %s\n", thisNetwork->pAction1);
			printf("|-----Action2: %s\n", thisNetwork->pAction2);
			printf("|-----Direction1: %s\n", thisNetwork->pDirection1);
			printf("|-----Direction2: %s\n", thisNetwork->pDirection2);
			printf("|-----IPExpr1: %s\n", thisNetwork->pIPExpr1);
			printf("|-----IPExpr2: %s\n", thisNetwork->pIPExpr2);
			printf("|-----IFace: %s\n", thisNetwork->pIface);
			printf("|-----Limit: %s\n", thisNetwork->pLimit);
			break;
		}
		case ELEMENT_INVALID:
		{
			printf("INVALID\n");
			break;
		}
		default:
		{
			printf("UNKNOWN\n");
			break;
		}
	}

	if (node->pCommentBlock != NULL)
	{
		if (node->pCommentBlock->pCommentText != NULL)
			printf("|-----Comment Block: %s\n", node->pCommentBlock->pCommentText);
	}

	if (node->pEOLComment != NULL)
	{
		if (node->pEOLComment->pCommentText != NULL)
			printf("|-----EOL Comment: %s\n", node->pEOLComment->pCommentText);
	}

	if (node->pChild != NULL)
	{
		ParseNode *childNode = node->pChild;
		while (childNode != NULL)
		{
			print_node(childNode);
			childNode = childNode->pSibling;
		}
	}
}
