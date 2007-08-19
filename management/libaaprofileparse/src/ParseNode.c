#include <stdlib.h>
#include "Nodes.h"

ParseNode* new_parse_node(NodeType type, ParseNode *root)
{
	ParseNode *ret = (ParseNode *) malloc(sizeof(ParseNode));
	if (ret != NULL)
	{
		ret->mNodeType = type;
		ret->pCommentBlock = NULL;
		ret->pEOLComment = NULL;
		ret->pParent = NULL;
		ret->pChild = NULL;
		ret->pSibling = NULL;
		ret->pRootNode = root;
		ret->pVariableList = NULL;
		ret->pError = NULL;
		ret->pData = NULL;
	}

	return ret;
}

void free_parse_node(ParseNode *node)
{
	if (node != NULL)
	{
		free(node);
	}
}

void add_parse_node_sibling(ParseNode *node, ParseNode *sibling)
{
	if (node->pSibling == NULL)
		node->pSibling = sibling;
	else
		add_parse_node_sibling(node->pSibling, sibling);
}

void add_parse_node_child(ParseNode *node, ParseNode *child)
{
	child->pParent = node;
	if (node->pChild == NULL)
		node->pChild = child;
	else
		add_parse_node_sibling(node->pChild, child);
}

