#ifndef _PROFILETOOL_H_
#define _PROFILETOOL_H_

#ifndef HELP_FILE_LOCATION
#define HELP_FILE_LOCATION ""
#endif 

/**
 * @short AppArmor Profile Tool
 * @author Matt Barringer <mbarringer@suse.de>
 * @version 1.0
 */

class ProfileToolFrame; 
class ProfileTreeData;

/**
 * The wxApp class
 **/
class AppArmorProfileTool : public wxApp
{
	public:
		virtual bool OnInit();
		virtual int OnExit();
	private:
		ProfileToolFrame *frame;
};

/**
 * The main frame
 **/
class ProfileToolFrame : public wxFrame
{
	public:
		ProfileToolFrame(const wxString& title, 
				const wxPoint& pos, 
				const wxSize& pos, 
				const wxString& startingProfile, 
				const wxString& startingHighlight);
		~ProfileToolFrame();
		void CreateControls(const wxString &startingProfile,
					const wxString &startingHighlight);
		void ClearProfile();
		bool DeleteProfile(wxString& profile);
		void EnableSaveMenu(bool toggle);
		int FindTreeNodeAndHighlight(wxTreeItemId startingNode, wxString path);
		void LoadProfile(const wxString& profile, const wxString& highlight);
		void PopulateControls();
		void ProfileHasBeenModified();
		int ProfileNeedSaving();
		void ReloadProfile(const wxString &filePath);
		void ReplaceAll(const wxString searchText, 
				const wxString replaceText, 
				int matchCase, 
				int wholeWord);
		void RepopulateControl();
		int SaveCurrentProfile();

		// Event handlers
		void OnQuit(wxCommandEvent& event);
		void OnClose(wxCloseEvent &event);
		void OnAbout(wxCommandEvent& event);
		void OnSave(wxCommandEvent& event);
		void OnFind(wxCommandEvent& event);
		void OnSearchAllProfiles(wxCommandEvent& event);
		void OnReplace(wxCommandEvent& event);
		void OnSaveAs(wxCommandEvent& event);
		void OnHelp(wxCommandEvent& event );
		void OnDeleteProfile(wxCommandEvent &event);
		void OnReloadProfile(wxCommandEvent &event);
		void OnCheckSyntax(wxCommandEvent &event);
		void OnEditMenu(wxCommandEvent& event);
		void OnPreferences(wxCommandEvent& event);
		void OnNewProfile(wxCommandEvent& event);
		void OnProfileModified(wxStyledTextEvent &event);
		void OnTreeSelection(wxTreeEvent& event);
		void OnTreeContextMenu(wxTreeEvent& event);
		void OnOpenInclude(wxCommandEvent &event);
		void OnInsertInclude(wxCommandEvent &event);
		void OnUpdateUI(wxStyledTextEvent &event);
		void OnSize(wxSizeEvent& event);
		void OnFindButton(wxFindDialogEvent& event);
		void OnEndOfProfileReload(wxProcessEvent &event);

	private:
		wxTreeCtrl		*mpProfileTree;
		wxFindReplaceDialog	*mpFindDialog, *mpReplaceDialog;
		wxHtmlHelpController 	*mpHelpController;
		ProfileTextCtrl 	*mpProfileView;
		wxMenuBar 		*mpMenuBar;
		wxFindReplaceData 	mFindData, mReplaceData;
		wxTreeItemId 		mRootNode;
		wxTreeItemId 		mCurrentNode;
		wxSplitterWindow	*mpSplitterWindow;
		DECLARE_EVENT_TABLE()
};

/**
 * This class is used to keep track of what path goes with
 * what profile entry in the tree.
 */

class ProfileTreeData : public wxTreeItemData
{
	public:
		ProfileTreeData(const wxString& path) : mPath(path) {}
		wxString GetPath(void) { return mPath; }
	private:
		wxString mPath;
};

enum
{
	ID_MENU_FILE_NEW=1048,
	ID_MENU_FILE_PREFERENCES,
	ID_MENU_FILE_SAVE,
	ID_MENU_FILE_SAVE_AS,
	ID_MENU_HELP_ABOUT,
	ID_MENU_HELP_PROFILES,
	ID_MENU_EDIT_COPY,
	ID_MENU_EDIT_CUT,
	ID_MENU_EDIT_PASTE,
	ID_MENU_EDIT_UNDO,
	ID_MENU_EDIT_REDO,
	ID_MENU_EDIT_FIND,
	ID_MENU_EDIT_REPLACE,
	ID_MENU_EDIT_FIND_NEXT,
	ID_MENU_EDIT_SEARCH_ALL_PROFILES,
	ID_PREFERENCES_DIALOG,
	ID_TREE_CONTEXT_DELETE,
	ID_TREE_CONTEXT_RELOAD,
	ID_RELOAD_PROFILE_PROCESS,
	ID_PROFILE_TREE
};

#endif // _PROFILETOOL_H_
