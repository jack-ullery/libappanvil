#ifndef __DATA_NODES_H__
#define __DATA_NODES_H__

#include "Nodes.h"

/**
 * Creates a new ParseError struct, which is used to give details
 * about parse errors.
 * @return ParseError struct.
 */
extern ParseError *new_parse_error(void);
/**
 * Frees all memory associated with a ParseError.
 * @param[in] The data to free.
 */
extern void free_parse_error(ParseError *error);

/**
 * Creates a new Capability node, which represents
 * apparmor syntax like "capability sys_admin".
 * @return Capability struct.
 */
extern Capability *new_capability_node(void);

extern char *capability_node_to_string(Capability *capability);

/**
 * Frees all memory associated with a Capability node.
 * @param[in] The data to free.
 */
extern void free_capability_node(Capability *node);

/**
 * Creates a new ChangeProfile node, which represents
 * the "change_profile /path/to/profile ," rule.
 */
extern ChangeProfile *new_change_profile_node(void);

extern char *change_profile_to_string(ChangeProfile *node);

/**
 * Frees all data associated with a ChangeProfile node.
 * @param[in] The data to free.
 */
extern void free_change_profile_node(ChangeProfile *node);

/**
 * Creates a new Comment node.
 * 
 * @param[in] The text of the comment.  Feel free to pass NULL.
 *
 */
extern Comment *new_comment_node(char *comment);

extern char *comment_node_to_string(Comment *node);
/**
 * Frees all data associated with a Comment node.
 * @param[in] The data to free.
 */
extern void free_comment_node(Comment *node);

/**
 * Creates a new Conditional node, which can either represent the
 * "if (EXPRESSION)" syntax, or the "else { }" syntax.  Conditional
 * nodes have two ParseNode pointers - one for the if data, one for the else
 * data.
 */
extern Conditional *new_conditional_node(void);

extern char *conditional_node_to_string(Conditional *node);

/**
 * Evaluates the ConditionalExpr a Conditional node contains.  It will return 
 * the IF, the ELSE, or a NULL ParseNode depending on whether or not
 * the ConditionalExpr evaluates to TRUE, FALSE, or FALSE without an else branch.
 *
 * @param[in] The conditional node to evaluate.
 * @param[in] A variable list to be used in the evaluation process.
 * @return A ParseNode tree of rules, or NULL.
 */
extern ParseNode *evaluate_conditional(Conditional *node, VariableList *list);

/**
 * Evaluates whether or not an individual ConditionalExpr is true or false.
 *
 * @param[in] The expression to evaluate.
 * @param[in] A variable list to be used in the evaluation process.
 * @return 0 - false, 1 - true.
 */
extern int evaluate_conditional_expr(ConditionalExpr *expr, VariableList *list);
/**
 * Frees all data associated with a conditional node, including it's ConditionalExpr
 * pointer, and the two ParseNode pointers.
 *
 * @param[in] The data to free.
 */
extern void free_conditional_node(Conditional *node);

/**
 * Creates a new ConditionalExpr node.
 */
extern ConditionalExpr *new_conditional_expr_node(void);
extern char *conditional_expr_to_string(ConditionalExpr *node);

/**
 * Frees all data associated with a ConditionalExpr node.
 * @param[in] The data to free.
 */
extern void free_conditional_expr_node(ConditionalExpr *node);

/**
 * Creates a new File node.
 */
extern File *new_file_node(void);
/**
 * Frees all data associated with a File node.
 * @param[in] The data to free.
 */
extern void free_file_node(File *node);

/**
 * Creates a new Function node.
 */
extern Function *new_function_node(void);
extern char *function_node_to_string(Function *node);

/**
 * Frees all data associated with a Function node.
 * @param[in] The data to free.
 */
extern void free_function_node(Function *node);

/**
 * Creates a new Group node.
 * @param[in] The ELEMENT_GROUP_TYPE of the group.
 */
extern Group *new_group_node(GroupType type);

extern char *group_node_to_string(Group *node);

/**
 * Frees all data associated with a Group node.
 * @param[in] The data to free.
 */
extern void free_group_node(Group *node);

/**
 * Creates a new Include node.
 */
extern Include *new_include_node(void);
extern char *include_node_to_string(Include *node);

/**
 * Frees all data associated with an Include node.
 * @param[in] The data to free.
 */
extern void free_include_node(Include *node);

/**
 * Creates a new Network node.
 */
extern Network *new_network_node(void);
extern char *network_node_to_string(Network *node);

/**
 * Frees all data associated with a Network node.
 * @param[in] The data to free.
 */
extern void free_network_node(Network *node);

/**
 * Creates a new Option node.
 */
extern Option *new_option_node(void);
extern char *option_node_to_string(Option *node);

/**
 * Frees all data associated with an Option node.
 * @param[in] The data to free.
 */
extern void free_option_node(Option *node);

/**
 * Creates a new Rule node.
 */
extern Rule *new_rule_node(void);
extern char *rule_node_to_string(Rule *node);
/** 
 * Frees all data associated with a Rule node.
 * @param[in] The data to free.
 */
extern void free_rule_node(Rule *node);

/**
 * Creates a new VariableAssignment node.
 */
extern VariableAssignment *new_variable_assignment_node(void);
extern char *variable_assignment_node_to_string(VariableAssignment *node);

/**
 * Frees all data associated with a VariableAssignment node.
 */
extern void free_variable_assignment_node(VariableAssignment *node);

/**
 * Creates a new Variable list
 */
extern VariableList *new_variable_list(void);

/**
 * Adds a VariableListEntry to the variable list.
 * @param[in] The root node of the VariableList to add the node to.
 * @param[in] The VariableListEntry to add.
 */
extern void add_variable_list_entry(VariableList *list, VariableListEntry *entry);

/**
 * A function to find a VariableList node by name.
 * @param[in] The root node of the VariableList to search
 * @param[in] The name of the variable to find.
 * @return A VariableList node matching the variable name, or NULL
 */
extern VariableList *find_variable_list_by_name(VariableList *list, char *name);
/**
 * Appends the values from one list variable (append_name) to another (name).
 * @param[in] The root node of the VariableList both VariableListEntries are attached to.
 * @param[in] The name of the variable to append the values to.
 * @param[in] The name of the variable to copy the values from.
 */
extern void append_variable_list_values(VariableList *list, char *name, char *append_name);

/**
 * Removes a specific VariableList node from the VariableList chain.  It will either return
 * a pointer to the existing root of the VariableList, or the a new root if the root node
 * turns out to have been the node deleted.
 * @param[in] The root node of the VariableList to search in.
 * @param[in] The name of the variable to remove.
 * @return The new root node.
 */
extern VariableList *del_variable_list_by_name(VariableList *rootList, char *name);
/**
 * Frees all memory associated with the entire VariableList linked list, including all
 * associated VariableListEntries.
 * @param[in] The root node of the VariableList chain to free.
 */
extern void free_entire_variable_list(VariableList *list);

/**
 * Frees all memory associated with a specific VariableList node, including the VariableListEntries.
 * @param[in] The VariableList to free.
 */
extern void del_variable_list(VariableList *list);

/**
 * Creates a new VariableListEntry
 */
extern struct _VariableListEntry *new_variable_list_entry(void);
/**
 * Adds a sibling to the VariableListEntry chain.
 * @param[in] The entry to be added to.
 * @param[in] The entry to add.
 */
extern void variable_list_entry_add_sibling(VariableListEntry *first, VariableListEntry *sibling);

/**
 * Frees all memory associated with a specific VariableListEntry
 * @param[in] The data to free.
 */
extern void del_variable_list_entry(VariableListEntry *entry);

/**
 * Frees all memory associated with a VariableListEntry chain.
 * @param[in] The root node of the list to free.
 */
extern void free_variable_list_entries(VariableListEntry *entry);


#endif
