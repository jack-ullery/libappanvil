#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#define DEFAULT_COMMENT_COLOUR 31, 31, 210
#define DEFAULT_INCLUDE_COLOUR 56, 136, 31
#define DEFAULT_CAP_COLOUR 229, 33, 204
#define DEFAULT_PATH_COLOUR 1, 1, 1
#define DEFAULT_PERM_COLOUR 160, 32, 240

class wxConfig;

/**
 * The configuration details class
 */
class Configuration
{
public:
	static void Initialize();
	static wxString BestGuessProfileDirectory();
	static wxString BestGuessParserCommand();
	static bool CommitChanges();

	static wxString GetProfileDirectory() { return mProfileDirectory; }
	static wxString GetEditorExecutable() { return mProfileEditorExecutable; }
	static wxString GetTemplateText() { return mTemplateText; }
	static wxString GetParserCommand() { return mParserCommand; }
	static wxColour GetCommentColour() { return mCommentColour; }
	static wxColour GetIncludeColour() { return mIncludeColour; }
	static wxColour GetCapColour() 	{ return mCapColour; }
	static wxColour GetPathColour() { return mPathColour; }
	static wxColour GetPermColour() { return mPermColour; }
	static wxFont GetCapabilityFont() { return mCapabilityFont; }
	static wxFont GetCommentFont() { return mCommentFont; }
	static wxFont GetIncludeFont() { return mIncludeFont; }
	static wxFont GetPathFont() { return mPathFont; }
	static wxFont GetPermFont() { return mPermsFont; }

	static void SetProfileDirectory(const wxString& profileDirectory) { mProfileDirectory = profileDirectory; }
	static void SetEditorExecutable(const wxString& executable) { mProfileEditorExecutable = executable; }
	static void SetParserCommand(const wxString& parserCommand) { mParserCommand = parserCommand; }
	static void SetTemplateText(const wxString& templateText) { mTemplateText = templateText; }
	static void SetCommentColour(const wxColour& commentColour) { mCommentColour = commentColour; }
	static void SetIncludeColour(const wxColour& includeColour) { mIncludeColour = includeColour; }
	static void SetCapColour(const wxColour& capColour) { mCapColour = capColour; }
	static void SetPathColour(const wxColour& pathColour) { mPathColour = pathColour; }
	static void SetPermColour(const wxColour& permColour) { mPermColour = permColour; }
	static void SetCapabilityFont(const wxFont& capabilityFont) { mCapabilityFont = capabilityFont; }
	static void SetCommentFont(const wxFont& commentFont) { mCommentFont = commentFont; }
	static void SetIncludeFont(const wxFont& includeFont) { mIncludeFont = includeFont; }
	static void SetPathFont(const wxFont& pathFont) { mPathFont = pathFont; }
	static void SetPermFont(const wxFont& permsFont) { mPermsFont = permsFont; }

private:
	static void		_WriteColour(const wxString& key, const wxColour& colour);
	static wxColour		_ReadColour(const wxString& key, const wxColour& defaultColour);
	static void		_ReadFont(const wxString& key, wxFont& font);
	static wxString		mProfileDirectory;
	static wxString		mProfileEditorExecutable;
	static wxString		mParserCommand;
	static wxString		mTemplateText;
	static wxColour		mCommentColour;
	static wxColour		mIncludeColour;
	static wxColour		mCapColour;
	static wxColour		mPathColour;
	static wxColour		mPermColour;
	static wxFont		mCapabilityFont;
	static wxFont		mCommentFont;
	static wxFont		mIncludeFont;
	static wxFont		mPathFont;
	static wxFont		mPermsFont;

};


#endif

