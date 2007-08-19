#ifndef __PARSE_NODE_H__
#define __PARSE_NODE_H__

#include "Nodes.h"

/**
 * Creates a new parse node.  It is up to the user to then set
 * the details.
 * @param[in] The node type.
 * @param[in] The root node of the tree.
 * @return A freshly allocated parse node.
 */
ParseNode *new_parse_node(NodeType type, ParseNode *root);
/**
 * Frees all data associated with a parse node.
 * @param[in] The node to free.
 */
void free_parse_node(ParseNode *node);

/**
 * Adds a child ParseNode to a parent ParseNode.
 * @param[in] The parent parse node.
 * @param[in] The child to add.
 */
void add_parse_node_child(ParseNode *node, ParseNode *child);

/**
 * Adds a sibling to a ParseNode.
 * @param[in] The 'elder' ParseNode (the one on the left side of the list).
 * @param[in] The sibling to add.
 */
void add_parse_node_sibling(ParseNode *node, ParseNode *sibling);

#endif

