#ifndef __AAPARSE_NODES_H__
#define __AAPARSE_NODES_H__

/**
 * Bits used for group flags
 **/
#define GROUP_FLAG_DISABLED 1
#define GROUP_FLAG_AUDIT 2
#define GROUP_FLAG_COMPLAIN 4
#define GROUP_FLAG_FOLD_HATS 8

#include "Types.h"

typedef struct _ParseError
{
	int mLine, mPos;
	ParseErrorType mErrorType;
	char *pName, *pMessage;
} ParseError;

/* A hash table could be used here, but I'm not sure that 
 * it would be necessary, since I doubt that people will 
 * be using a great deal of variables in their profiles.
 */
typedef struct _VariableListEntry
{
	int 				mIsBoolValue;
	char				*pName;
	union {
		char			*pValue;
		int			mBoolValue;
	} mValues;
	struct _VariableListEntry	*pNext, *pBack;
} VariableListEntry;

typedef struct _VariableList
{
	char			*pName;
	VariableListEntry	*pFirstEntry;
	struct _VariableList	*pBack, *pNext;
} VariableList;


typedef struct _Comment
{
	char			*pCommentText;
} Comment;

typedef struct _ParseNode
{
	int			mError;
	ParseError		*pError;
	NodeType		mNodeType;
	Comment			*pCommentBlock;
	Comment			*pEOLComment;
	VariableList		*pVariableList;
	struct _ParseNode	*pRootNode, *pParent, *pChild, *pSibling;
	void			*pData;
} ParseNode;

typedef struct _Capability
{
	char			*pCapability;
} Capability;

typedef struct _ChangeProfile
{
	char			*pProfile;
} ChangeProfile;

typedef struct _ConditionalExpr
{
	CondExprType		mCondType;
	CondExprLinkType	mLinkType;
	int			mNegated;
	char			*pExprVariable;
	struct _ConditionalExpr *pBack, *pNext;
} ConditionalExpr;

typedef struct _Conditional
{
	ConditionalExpr		*pExpr;
	char			*pConditionalString;
	ParseNode		*pIfBranch;
	ParseNode		*pElseBranch;
} Conditional;

typedef struct _File
{
	char			*pFilePath;
	char			*pFileName;
} File;

typedef struct _Function
{
	FunctionType		mFunctionType;
	char			*pFunctionInput;
} Function;

typedef struct _Group
{
	GroupType	mGroupType;
	char		*pIdentifier;
	char		mFlags;
} Group;

typedef struct _Include
{
	char		*pIncludeFile;
} Include;

typedef struct _Network
{
	int		mConntrack;
	char		*pDomain;
	char		*pType;
	char		*pProtocol;
	char		*pAction1;
	char		*pAction2;
	char		*pDirection1;
	char		*pDirection2;
	char		*pIPExpr1;
	char		*pIPExpr2;
	char		*pIface;
	char		*pLimit;
} Network;

typedef struct _Option
{
	OptionType	mOptionType;
	union {
		int	mBoolValue;
		char	*pCharValue;
	} mValue;
} Option;

typedef struct _Rule
{
	/* The path as it is in the profile */
	char		*pResource;

	/* If a path uses variables, the variables
	 * will be expanded and inserted approriately
	 * into this string.
	 */
	char		*pExpandedResource;
	int		mPerms;
	char*		pPermString;
} Rule;

typedef struct _VariableAssignment
{
	int		mIsBoolValue;
	int		mPlusEquals; /* If 0, it's an '=' assignment, if 1, it's '+=' */
	char		*pName;
	char		*pValue;
} VariableAssignment;

#endif
