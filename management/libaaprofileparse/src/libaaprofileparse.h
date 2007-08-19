#ifndef __LIBAAPROFILEPARSE_H__
#define __LIBAAPROFILEPARSE_H__

#include "Nodes.h"
#include "ParseNode.h"
#include "DataNodes.h"

#define AA_PROFILE_DIR "/home/matt/"

/**
 * Parses a profile, returning a parse tree.
 *
 * @param[in] The filename to parse.
 * @return A full parse tree.
 */
ParseNode *parse_file (char *file);

/**
 * Frees up all data associated with the parse tree.
 * @param[in] The parse tree to free.
 */
void cleanup_parse_tree(ParseNode *tree);

#endif


