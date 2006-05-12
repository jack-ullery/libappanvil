/*	AppArmor Profile Editor (C) 2006 Novell, Inc.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 * 
 */

// TODO:
// * Find box in profile list
// * Go through and make sure that translation will work correctly

#include "wx/wxprec.h"

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

#include <wx/treectrl.h> // For profileTree
#include <wx/dir.h> // Various functions
#include <wx/filedlg.h> // Save As dialog
#include <wx/cmdline.h> // For launching apps
#include <wx/html/helpctrl.h> // The help window
#include <wx/fs_zip.h> // Needed by the help window
#include <wx/process.h> // For forking off the profile reload process
#include <wx/wfstream.h> // Used by the profile reload function
#include <wx/fdrepdlg.h> // Find/Replace dialog

#include "ProfileTextCtrl.h"
#include "AboutDialog.h"
#include "profileeditor.h"
#include "ProfileDirectoryTraverser.h"
#include "Preferences.h"
#include "SearchAllProfiles.h"
#include "Configuration.h"

BEGIN_EVENT_TABLE( ProfileToolFrame, wxFrame )
	EVT_END_PROCESS(ID_RELOAD_PROFILE_PROCESS, ProfileToolFrame::OnEndOfProfileReload)
	EVT_FIND(wxID_ANY, ProfileToolFrame::OnFindButton)
	EVT_FIND_NEXT(wxID_ANY, ProfileToolFrame::OnFindButton)
	EVT_FIND_REPLACE(wxID_ANY, ProfileToolFrame::OnFindButton)
	EVT_FIND_REPLACE_ALL(wxID_ANY, ProfileToolFrame::OnFindButton)
	EVT_FIND_CLOSE(wxID_ANY, ProfileToolFrame::OnFindButton)
	EVT_MENU(wxID_EXIT, ProfileToolFrame::OnQuit)
	EVT_MENU(ID_MENU_FILE_NEW, ProfileToolFrame::OnNewProfile)
	EVT_MENU(ID_MENU_FILE_PREFERENCES, ProfileToolFrame::OnPreferences)
	EVT_MENU(ID_MENU_HELP_ABOUT, ProfileToolFrame::OnAbout)
	EVT_MENU(ID_MENU_FILE_SAVE, ProfileToolFrame::OnSave)
	EVT_MENU(ID_MENU_FILE_SAVE_AS, ProfileToolFrame::OnSaveAs)
	EVT_MENU(ID_MENU_HELP_PROFILES, ProfileToolFrame::OnHelp)
	EVT_MENU(ID_MENU_EDIT_COPY, ProfileToolFrame::OnEditMenu)
	EVT_MENU(ID_MENU_EDIT_CUT, ProfileToolFrame::OnEditMenu)
	EVT_MENU(ID_MENU_EDIT_PASTE, ProfileToolFrame::OnEditMenu)
	EVT_MENU(ID_MENU_EDIT_UNDO, ProfileToolFrame::OnEditMenu)
	EVT_MENU(ID_MENU_EDIT_REDO, ProfileToolFrame::OnEditMenu)
	EVT_MENU(ID_MENU_EDIT_FIND, ProfileToolFrame::OnFind)
	EVT_MENU(ID_MENU_EDIT_REPLACE, ProfileToolFrame::OnReplace)
	EVT_MENU(ID_MENU_EDIT_SEARCH_ALL_PROFILES, ProfileToolFrame::OnSearchAllProfiles)
	EVT_MENU(ID_TREE_CONTEXT_DELETE, ProfileToolFrame::OnDeleteProfile)
	EVT_MENU(ID_TREE_CONTEXT_RELOAD, ProfileToolFrame::OnReloadProfile)
	EVT_MENU(wxSTC_APPARMOR_OPEN_INCLUDE_MENU_ITEM, ProfileToolFrame::OnOpenInclude)
	EVT_MENU(wxSTC_APPARMOR_INSERT_INCLUDE_MENU_ITEM, ProfileToolFrame::OnInsertInclude)
	EVT_MENU(wxSTC_APPARMOR_SEARCH_PHRASE_IN_ALL_PROFILES, ProfileToolFrame::OnSearchAllProfiles)
	EVT_TREE_ITEM_ACTIVATED(ID_PROFILE_TREE, ProfileToolFrame::OnTreeSelection)
	EVT_TREE_ITEM_MENU(ID_PROFILE_TREE, ProfileToolFrame::OnTreeContextMenu)
	EVT_STC_CHANGE(ID_STYLED_PROFILE_WINDOW, ProfileToolFrame::OnProfileModified)
	EVT_STC_UPDATEUI(ID_STYLED_PROFILE_WINDOW, ProfileToolFrame::OnUpdateUI)
	EVT_SIZE(ProfileToolFrame::OnSize)
	EVT_CLOSE(ProfileToolFrame::OnClose)
END_EVENT_TABLE()

IMPLEMENT_APP(AppArmorProfileTool)
	
/**
 * The standard wxApp OnInit function
 * @return Success or fail
 */
bool AppArmorProfileTool::OnInit()
{
	wxApp::SetAppName(_T("AppArmorProfileEditor"));
	wxString startingProfile = wxEmptyString;
	wxString startingHighlight = wxEmptyString;
	
	// Set up the command line parser
	// usage: profileeditor [profile to open] [phrase to highlight]
	wxCmdLineEntryDesc commandLineDesc[3];
	commandLineDesc[0].kind = wxCMD_LINE_PARAM;
	commandLineDesc[0].shortName = NULL;
	commandLineDesc[0].longName = NULL;
	commandLineDesc[0].description = _("Path to profile");
	commandLineDesc[0].type = wxCMD_LINE_VAL_STRING;
	commandLineDesc[0].flags = wxCMD_LINE_PARAM_OPTIONAL;
	commandLineDesc[1].kind = wxCMD_LINE_PARAM;
	commandLineDesc[1].shortName = NULL;
	commandLineDesc[1].longName = NULL;
	commandLineDesc[1].description = _("Search phrase to highlight");
	commandLineDesc[1].type = wxCMD_LINE_VAL_STRING;
	commandLineDesc[1].flags = wxCMD_LINE_PARAM_OPTIONAL;
	commandLineDesc[2].kind = wxCMD_LINE_NONE; // End the list

	// See if they gave us a profile to load
	wxCmdLineParser parser(commandLineDesc, argc, argv);
	int parserReturn = parser.Parse(true);

	if (0 == parserReturn) // Successful parsing
	{
		int results = parser.GetParamCount();
		if (results >= 1)
				startingProfile = parser.GetParam(0);

		if (results >= 2)
				startingHighlight = parser.GetParam(1);
	}
	else
	{
		return FALSE;
	}

	// No sense in letting them any further if they aren't root
// 	if (geteuid() != 0) {
// 		wxMessageDialog *dlg = new wxMessageDialog(NULL, 
// 						_T("You must be root to run this program."), _T("Error"), 
// 						wxOK|wxICON_ERROR);
// 		dlg->ShowModal();
// 		dlg->Destroy();	
// 		return FALSE;
// 	}

	frame = new ProfileToolFrame(_("AppArmor Profile Editor" ), 
				wxPoint(50,50),
				wxSize(640,480),
				startingProfile,
				startingHighlight);
	frame->Show(TRUE);
	SetTopWindow(frame);
	return TRUE;
} 

/**
 * This isn't actually used
 * @return 
 */
int AppArmorProfileTool::OnExit()
{
	return 0;
}

ProfileToolFrame::ProfileToolFrame(const wxString& title, 
					const wxPoint& pos, 
					const wxSize& size, 
					const wxString &startingProfile,
					const wxString &startingHighlight)
	: wxFrame((wxFrame *) NULL, -1, title, pos, size)
{
	mpProfileTree = NULL;
	mpFindDialog = NULL;
	mpReplaceDialog = NULL;
	mpProfileView = NULL;
	mpMenuBar = NULL;
	

	wxFileSystem::AddHandler(new wxZipFSHandler); // Needed by the help handler
	if (wxFileExists(_(HELP_FILE_LOCATION)))
	{
		mpHelpController = new wxHtmlHelpController;
		mpHelpController->Initialize(_(HELP_FILE_LOCATION));
	}
	else
	{
		mpHelpController = NULL;
	}

	// I have no idea why "search up" is the default, 
	// but I suspect most people will expect otherwise
	mFindData.SetFlags(wxFR_DOWN);
	mReplaceData.SetFlags(wxFR_DOWN);
	CreateControls(startingProfile, startingHighlight);
}

ProfileToolFrame::~ProfileToolFrame() 
{
	delete mpHelpController;
	delete wxConfig::Get();
}

/**
 * The great big nasty function that puts the main frame together.
 *
 * @param startingProfile The initial profile to open
 * @param startingHighlight A phrase to highlight
 */
void ProfileToolFrame::CreateControls(const wxString &startingProfile, const wxString &startingHighlight)
{
	Configuration::Initialize();
	// Set up our menu
	wxMenu* menuFile = new wxMenu;
	wxMenu* menuEdit = new wxMenu;
	wxMenu* menuHelp = new wxMenu;
	CreateStatusBar();
	menuFile->Append(ID_MENU_FILE_NEW, _("&New Profile\tCtrl-N"));
	menuFile->Append(ID_MENU_FILE_SAVE, _("&Save Profile\tCtrl-S"));
	menuFile->Append(ID_MENU_FILE_SAVE_AS, _("Save Profile As..."));
	menuFile->Append(ID_MENU_FILE_PREFERENCES, _("&Preferences...\tCtrl-P"));
	menuFile->AppendSeparator();
	menuFile->Append(wxID_EXIT, _("E&xit\tCtrl-Q"));
	menuEdit->Append(ID_MENU_EDIT_UNDO, _("&Undo\tCtrl-Z"));
	menuEdit->Append(ID_MENU_EDIT_REDO, _("&Redo\tShift-Ctrl-Z"));
	menuEdit->AppendSeparator();
	menuEdit->Append(ID_MENU_EDIT_CUT, _("C&ut\tCtrl-X"));
	menuEdit->Append(ID_MENU_EDIT_COPY,_("C&opy\tCtrl-C"));
	menuEdit->Append(ID_MENU_EDIT_PASTE, _("P&aste\tCtrl-V"));
	menuEdit->AppendSeparator();
	menuEdit->Append(ID_MENU_EDIT_FIND, _("&Find\tCtrl-F"));
	menuEdit->Append(ID_MENU_EDIT_FIND_NEXT, _("Fin&d Next\tF3"));
	menuEdit->Append(ID_MENU_EDIT_REPLACE, _("R&eplace\tCtrl-H"));
	menuEdit->AppendSeparator();
	menuEdit->Append(ID_MENU_EDIT_SEARCH_ALL_PROFILES, _("&Search all profiles\tAlt-Ctrl-F"));
	menuHelp->Append(ID_MENU_HELP_ABOUT, _("A&bout"));
	menuHelp->Append(ID_MENU_HELP_PROFILES, _("P&rofiles\tF1"));
	mpMenuBar = new wxMenuBar;
	mpMenuBar->Append(menuFile, _("&File"));
	mpMenuBar->Append(menuEdit, _("&Edit"));
	mpMenuBar->Append(menuHelp, _("&Help"));

	mpMenuBar->Enable(ID_MENU_FILE_SAVE, false);
	mpMenuBar->Enable(ID_MENU_FILE_SAVE_AS, false);
	mpMenuBar->Enable(ID_MENU_EDIT_UNDO, false);
	mpMenuBar->Enable(ID_MENU_EDIT_REDO, false);
	mpMenuBar->Enable(ID_MENU_EDIT_FIND_NEXT, false);	
	SetMenuBar( mpMenuBar );
	
	// Restore the user's window position if there was one
	Move(Configuration::GetWindowPos());
	SetSize(Configuration::GetWindowSize());

	mpSplitterWindow = new wxSplitterWindow(this, 
				wxID_ANY, 
				wxDefaultPosition, 
				GetClientSize(), wxSP_3D| wxEXPAND);
 	
//	The tree control displays the list of profiles.
	mpProfileTree = new wxTreeCtrl(mpSplitterWindow, ID_PROFILE_TREE, wxDefaultPosition, wxDefaultSize,
					wxTR_HAS_BUTTONS
					| wxTR_SINGLE);
	mpProfileView = new ProfileTextCtrl (mpSplitterWindow, 
					ID_STYLED_PROFILE_WINDOW, 
					wxDefaultPosition, 
					wxDefaultSize);
	mpSplitterWindow->SplitVertically(mpProfileTree, mpProfileView, 200);
	mpSplitterWindow->SetMinimumPaneSize(20);
	
	mRootNode = mpProfileTree->AddRoot(_("Profiles"));
	mCurrentNode.Unset();
	PopulateControls(); // Load up the profile tree

	mpProfileView->SetFileName(_T(""));
	mpProfileView->SetIsNew(true);
	SetStatusText(_("New Profile"));
	SetTitle(_("New Profile"));
	
	if ((wxEmptyString != startingProfile) && wxFileExists(startingProfile))
	{
		LoadProfile(startingProfile, startingHighlight);
		FindTreeNodeAndHighlight(mRootNode, startingProfile);
	}

	mpMenuBar->Enable(ID_MENU_EDIT_PASTE, mpProfileView->CanPaste());	
}

/**
 * Clears the current text window
 */
void ProfileToolFrame::ClearProfile()
{
	mpMenuBar->Enable(ID_MENU_FILE_SAVE, false);
	mpMenuBar->Enable(ID_MENU_FILE_SAVE_AS, false);
	mpMenuBar->Enable(ID_MENU_EDIT_UNDO, false);
	mpMenuBar->Enable(ID_MENU_EDIT_REDO, false);
	SetStatusText(_("New profile"));
	SetTitle(_("New Profile"));
	mpProfileView->SetIgnoreChanges(true);
	mpProfileView->SetFileName(_(""));
	mpProfileView->ClearAll();
	mpProfileView->EmptyUndoBuffer();
	mpProfileView->SetText(Configuration::GetTemplateText());
	mpProfileView->SetIsNew(true); // It's a new profile
	mpProfileView->SetNeedSaving(false);
	if (mCurrentNode.IsOk())
		mpProfileTree->SetItemTextColour(mCurrentNode, *wxBLACK);
	mpProfileView->SetIgnoreChanges(false);
}

/**
 * Deletes a profile from disk.
 *
 * @param profile 
 * @return Successful delete or not
 */
bool ProfileToolFrame::DeleteProfile(wxString &profile)
{
	return wxRemoveFile(profile);
}

/**
 * Given a path to a profile, find it in the tree, and highlight it.
 * This is only used when a profile is passed via argv.
 * @param startingNode The node to start at
 * @param path Path to the profile
 * @return 0 on success, -1 on failure
 */
int ProfileToolFrame::FindTreeNodeAndHighlight(wxTreeItemId startingNode, wxString path)
{
	wxTreeItemIdValue cookie;
	wxTreeItemId search;
	wxTreeItemId node = mpProfileTree->GetFirstChild(startingNode, cookie );
	wxTreeItemId child;
	ProfileTreeData *data;

	while(node.IsOk())
	{
		if (mpProfileTree->ItemHasChildren(node))
		{
			if (0 == FindTreeNodeAndHighlight(node, path))
				return 0;
		}
		else
		{
			data = (ProfileTreeData *) mpProfileTree->GetItemData(node);
			if (NULL != data)
			{
				if (data->GetPath() == path)
				{
					// Whee, found it.  Highlight it
					if (mCurrentNode.IsOk())
						mpProfileTree->SetItemTextColour(mCurrentNode, *wxBLACK);
					mCurrentNode = node;
					mpProfileTree->SetItemTextColour(mCurrentNode, *wxBLUE);
					mpProfileTree->SelectItem(mCurrentNode);
					mpProfileTree->EnsureVisible(mCurrentNode);
					return 0;
				}
			}
		}
		node = mpProfileTree->GetNextChild(startingNode, cookie);
	}

	return -1; // Couldn't find it
} 

/**
 * Load a profile from disk into the profile view
 * @param profile Profile to load
 * @param highlight Text to highlight
 */
void ProfileToolFrame::LoadProfile (const wxString& profile, const wxString& highlight)
{

	if (mpProfileView->LoadFile(profile))
	{
		// Select the first instance of a phrase.  This is used primarily
		// when a user runs a "search all profiles"
		if (wxEmptyString != highlight) 
		{
			int searchResult = mpProfileView->FindText(0,
						mpProfileView->GetTextLength(), 
						highlight,
						0 | 0);
			if (searchResult >= 0)
			{
				mpProfileView->SetCurrentPos(searchResult + highlight.Length());
				mpProfileView->SetSelection(searchResult, searchResult + highlight.Length());		
			}
	
		}
	
		SetStatusText(profile);
		SetTitle(profile);
	
		// Reset the save menu items until we're notified of a modification
		mpMenuBar->Enable(ID_MENU_FILE_SAVE, false);
		mpMenuBar->Enable(ID_MENU_FILE_SAVE_AS, false);
		mpMenuBar->Enable(ID_MENU_EDIT_UNDO, false);
		mpMenuBar->Enable(ID_MENU_EDIT_REDO, false);
	}
}

/**
 * Scans through the default profile directory and loads the names into
 * the profile tree.
 */
void ProfileToolFrame::PopulateControls()
{
	// Scan the directory structure
	ProfileDirectoryTraverser traverser (mpProfileTree, mRootNode, Configuration::GetProfileDirectory());
	wxDir dir (Configuration::GetProfileDirectory());
	dir.Traverse(traverser, wxEmptyString);
	mpProfileTree->SortChildren(mRootNode);
	mpProfileTree->Expand(mRootNode);
}

/**
 * Called when text in the profile view has been changed, enabling the Save(As) menu functions
 */
void ProfileToolFrame::ProfileHasBeenModified()
{
	if (!mpProfileView->GetIsNew()) // Don't let them "Save" unless we have a filename
		mpMenuBar->Enable(ID_MENU_FILE_SAVE, true); 
	mpMenuBar->Enable(ID_MENU_FILE_SAVE_AS, true);
	mpMenuBar->Enable(ID_MENU_EDIT_UNDO, mpProfileView->CanUndo());
	mpMenuBar->Enable(ID_MENU_EDIT_REDO, mpProfileView->CanRedo());
	if ((mCurrentNode != mRootNode) && mCurrentNode.IsOk())
		mpProfileTree->SetItemTextColour(mCurrentNode, *wxRED);
	mpProfileView->SetNeedSaving(true);
}

/**
 * Asks the user whether or not they'd like to save the profile
 * @return -1 on "Cancel", 0 on a successful save, 1 on "No"
 */
int ProfileToolFrame::ProfileNeedSaving ()
{
	int ret = -1;
	switch (wxMessageBox(_("Would you like to save your active profile?"),
			 _("Save Profile"),
			 wxICON_QUESTION | wxYES_NO | wxCANCEL))
	{
		case wxCANCEL:
			ret = -1;
			break;	
		case wxYES:
			ret = SaveCurrentProfile(); // This will either be 0 for successful save 
						    // or -1 for a failure
			break;
		case wxNO:
			ret = 1;
			break;
		default:
			ret = -1;
			break;
	}

	return ret;


}


/**
 * Feeds the profile to the AppArmor parser.
 * @param filePath 
 */
void ProfileToolFrame::ReloadProfile (const wxString &filePath)
{
	wxString parserCommand = Configuration::GetParserCommand();
	parserCommand.Append(_(" -r "));
	wxProcess *proc = new wxProcess(this, ID_RELOAD_PROFILE_PROCESS); 
	proc->Redirect();
	wxExecute(parserCommand, wxEXEC_ASYNC, proc);
	wxFileInputStream inputStream (filePath);
	inputStream.Read(*proc->GetOutputStream());
	proc->GetOutputStream()->Close();
}

/**
 * Clears the tree and reloads the profile tree.  Used when someone modifies the
 * default profile directory in the preferences.
 */
void ProfileToolFrame::RepopulateControl()
{
	mCurrentNode = mRootNode;
	mpProfileTree->CollapseAndReset(mRootNode);	
	PopulateControls();
}

/**
 * Replaces all instances of a phrase, without user confirmation
 * @param searchText Text to search for
 * @param replaceText Replacement text
 * @param matchCase 
 * @param wholeWord 
 */
void ProfileToolFrame::ReplaceAll (const wxString searchText, const wxString replaceText, int matchCase, int wholeWord)
{
	int startResult, i;
	int len = searchText.Length();
	i = 0;
	startResult = mpProfileView->FindText(0, mpProfileView->GetTextLength(), 
				searchText,
 				matchCase | wholeWord);
	while (-1 != startResult)
	{
		mpProfileView->SetCurrentPos(startResult + len);
		mpProfileView->SetSelection(startResult, startResult +len);
		
		mpProfileView->ReplaceSelection(replaceText);
		startResult = mpProfileView->FindText(mpProfileView->GetCurrentPos(), 
							mpProfileView->GetTextLength(), 
							searchText, 
							matchCase | wholeWord);
		i++;
	}

	mpProfileView->SetNeedSaving(true);
	wxString informMessage;
	informMessage.Printf(_("Made %i replacements."), i);
	wxMessageDialog *dlg = new wxMessageDialog(this, 
					informMessage, 
					_("Finished"), 
					wxOK|wxICON_INFORMATION);
	dlg->ShowModal();
	dlg->Destroy();
}

/**
 * A small wrapper around the profile view's save function. 
 * @return -1 on failure, 0 on success
 */
int ProfileToolFrame::SaveCurrentProfile ()
{
	wxString filename = mpProfileView->GetFileName();
	if (mpProfileView->SaveFile(filename))
	{
		mpProfileView->SetNeedSaving(false);
		mpProfileTree->SetItemTextColour(mCurrentNode, *wxBLUE);
		return 0;
	}
	else
	{
		return -1;
	}
}

///////// Event handler functions

/**
 * Event handler triggered by the Help->About menu 
 * @param event 
 */
void ProfileToolFrame::OnAbout( wxCommandEvent& WXUNUSED(event) )
{
	AboutDialog *aboutDialog = new AboutDialog(this, wxID_ANY);
	aboutDialog->ShowModal();
	aboutDialog->Destroy();
}

/**
 * Event handler triggered by a close event
 * @param WXUNUSED( event ) 
 */
void ProfileToolFrame::OnClose( wxCloseEvent& WXUNUSED(event) )
{
	// Save our window settings
	wxPoint pos = GetPosition();
	wxSize size = GetSize();
	Configuration::WriteWindowSettings(GetPosition(), GetSize());
	if (mpProfileView->GetNeedSaving())
	{
		if (ProfileNeedSaving() != -1)
			Destroy();
	}
	else
	{
		Destroy();
	}
}


/**
 * Event handler triggered by the "Delete profile" tree context menu
 * @param event 
 */
void ProfileToolFrame::OnDeleteProfile(wxCommandEvent &event)
{
	wxString filePath;
	wxTreeItemId selectedId = mpProfileTree->GetSelection();
	ProfileTreeData *data = (ProfileTreeData *) mpProfileTree->GetItemData(selectedId);
	filePath = data->GetPath();

	switch (wxMessageBox(_("Are you sure you want to delete this profile?"),
			 _("Delete Profile"),
			 wxICON_QUESTION | wxYES_NO))
	{
		case wxYES:
			if (DeleteProfile(filePath))
			{
				// See if the profile we just deleted matches
				// what's currently in the editor
				if (mpProfileView->GetFileName() == filePath) // Yes, it is
				{
					mCurrentNode.Unset();
					ClearProfile();
				}
				// Remove the profile from the tree
				mpProfileTree->Delete(selectedId);
			}
			break;
		case wxNO:
			break;
		default:
			break;

	}
}

/**
 * Event handler for the Cut/Copy/Paste/Undo/Redo Edit menu events
 * @param event 
 */
void ProfileToolFrame::OnEditMenu(wxCommandEvent &event)
{
	switch(event.GetId())
	{
		case ID_MENU_EDIT_COPY:
			mpMenuBar->Enable(ID_MENU_EDIT_UNDO, mpProfileView->CanPaste());
			mpProfileView->Copy();
			break;
		case ID_MENU_EDIT_CUT:
			mpMenuBar->Enable(ID_MENU_EDIT_UNDO, mpProfileView->CanPaste());
			mpProfileView->Cut();
			break;
		case ID_MENU_EDIT_PASTE:
			mpProfileView->Paste();
			break;
		case ID_MENU_EDIT_UNDO:
			mpProfileView->Undo();
			mpMenuBar->Enable(ID_MENU_EDIT_UNDO, mpProfileView->CanUndo());
			mpMenuBar->Enable(ID_MENU_EDIT_REDO, mpProfileView->CanRedo());
			break;
		case ID_MENU_EDIT_REDO:
			mpProfileView->Redo();
			mpMenuBar->Enable(ID_MENU_EDIT_UNDO, mpProfileView->CanUndo());
			mpMenuBar->Enable(ID_MENU_EDIT_REDO, mpProfileView->CanRedo());
			break;
		default:
			break;
	}
}

/**
 * Event handler triggered by the end of the profile reload child
 * process.  Checks the exit code and reports success or failure to the user
 * @param event 
 */
void ProfileToolFrame::OnEndOfProfileReload(wxProcessEvent &event)
{
	wxMessageDialog *dlg;
	if (0 == event.GetExitCode())
	{
		dlg = new wxMessageDialog(this, _("Successfully reloaded profile."), _("Success"), 
				wxOK|wxICON_INFORMATION);
	}
	else
	{
		dlg = new wxMessageDialog(this, _("Reload failed!"), _("Error"), 
				wxOK|wxICON_ERROR);
	}
	
	dlg->ShowModal();
	dlg->Destroy();	

}

/**
 * Event handler triggered by the "Find" menu item
 * @param WXUNUSED(event)
 */
void ProfileToolFrame::OnFind (wxCommandEvent& WXUNUSED(event))
{
	if (mpProfileView->GetSelectedText() != _(""))
		mFindData.SetFindString(mpProfileView->GetSelectedText());
	mpProfileView->SetSelection(mpProfileView->GetCurrentPos(), mpProfileView->GetCurrentPos());
	mpFindDialog = new wxFindReplaceDialog (this, &mFindData, _("Find"));
	mpFindDialog->Show();
}

/**
 * Event handler triggered by the "Find" button in the Find/Replace dialog
 * @param event 
 */
void ProfileToolFrame::OnFindButton (wxFindDialogEvent& event)
{
	wxEventType type = event.GetEventType();
	int flags = event.GetFlags();
	int matchCase = (flags & wxFR_MATCHCASE) ? wxSTC_FIND_MATCHCASE : 0;
	int wholeWord = (flags & wxFR_WHOLEWORD) ? wxSTC_FIND_WHOLEWORD : 0;
	int startResult = 0;
	int len = event.GetFindString().Length();
	wxString searchText = event.GetFindString().c_str();

	if ( type == wxEVT_COMMAND_FIND || type == wxEVT_COMMAND_FIND_NEXT )
	{
		if (flags & wxFR_DOWN) 
		{
			startResult = mpProfileView->FindText(mpProfileView->GetCurrentPos(),
	 				mpProfileView->GetTextLength(), 
					searchText,
					matchCase | wholeWord);
		}
		else
		{
			mpProfileView->SearchAnchor(); // Sets the anchor to the current position
			startResult = mpProfileView->SearchPrev(matchCase | wholeWord, searchText);
		}

		// Move the cursor and highlight the text
		if (startResult >= 0)
		{
			mpProfileView->SetCurrentPos(startResult + len);
			mpProfileView->SetSelection(startResult, startResult +len);
			mpMenuBar->Enable(ID_MENU_EDIT_FIND_NEXT, true);
		}
		else 
		{
			mpProfileView->SetSelection(mpProfileView->GetCurrentPos(), mpProfileView->GetCurrentPos());
			mpMenuBar->Enable(ID_MENU_EDIT_FIND_NEXT, false);
			wxMessageDialog *dlg = new wxMessageDialog(this, 
						_("Finished searching the profile"), 
						_("Finished"), 
						wxOK|wxICON_INFORMATION);
			dlg->ShowModal();
			dlg->Destroy();
		}
	}

	else if (type == wxEVT_COMMAND_FIND_REPLACE) 
	{
		if (mpProfileView->GetSelectedText() != _T(""))
		{
			mpProfileView->ReplaceSelection(event.GetReplaceString());
			mpProfileView->SetNeedSaving(true);
		}	

		int startResult = -1;
		if (flags & wxFR_DOWN)
		{ 
			startResult = mpProfileView->FindText(mpProfileView->GetCurrentPos(), 
					mpProfileView->GetTextLength(), 
					searchText,
					matchCase | wholeWord);
		}
		else
		{
			mpProfileView->SearchAnchor();
			startResult = mpProfileView->SearchPrev(matchCase | wholeWord, searchText);
		}
			
		if (startResult != -1)
		{	
			mpProfileView->SetCurrentPos(startResult + len);
			mpProfileView->SetSelection(startResult, startResult + len);
		}
		else
		{
			mpProfileView->SetSelection(mpProfileView->GetCurrentPos(), mpProfileView->GetCurrentPos());
			wxMessageDialog *dlg = new wxMessageDialog(this, _("Finished searching the profile"), 
							_("Finished"),
							wxOK|wxICON_INFORMATION);
			dlg->ShowModal();
			dlg->Destroy();
		}
	}
	else if (type == wxEVT_COMMAND_FIND_REPLACE_ALL )
	{
		ReplaceAll(event.GetFindString(), event.GetReplaceString(), matchCase, wholeWord);
		wxFindReplaceDialog *dlg = event.GetDialog();
		dlg->Destroy();
	}
	else if (type == wxEVT_COMMAND_FIND_CLOSE)
	{
		wxFindReplaceDialog *dlg = event.GetDialog();
		dlg->Destroy();
	}

}

/**
 * Event handler triggered by the Help->Profiles menu item.
 * The help controller was loaded earlier, and if the help file
 * was not found AT THAT TIME, it will warn the user.
 * @param WXUNUSED( event ) 
 */
void ProfileToolFrame::OnHelp(wxCommandEvent& WXUNUSED(event))
{
	if (mpHelpController != NULL)
	{
	 	mpHelpController->DisplayContents();
	}
	else
	{
		wxString message = _("The help file was not in the expected place: ");
		message.Append(_(HELP_FILE_LOCATION));
		wxMessageDialog *dlg = new wxMessageDialog(this, message, 
									_("Error"), 
									wxOK|wxICON_ERROR);
		dlg->ShowModal();
		dlg->Destroy();			
	}
}

/**
 * Event handler triggered by the profile view's "Insert an include..."
 * context menu item.  It'll pop up a file selection dialog and insert the selection.
 * @param WXUNUSED(event)
 */
void ProfileToolFrame::OnInsertInclude (wxCommandEvent& WXUNUSED(event))
{
	wxFileDialog *includeFileDialog = new wxFileDialog(this, _("Choose files to include"),
							Configuration::GetProfileDirectory(),
								_T(""), _T("*.*"), wxOPEN|wxMULTIPLE);
	if (includeFileDialog->ShowModal() == wxID_OK)
	{
		wxArrayString paths;
		includeFileDialog->GetPaths(paths);
		int size = paths.GetCount();
		for (int i = 0; i < size; i++)
		{
			mpProfileView->AddText(_T("\n#include <"));
			mpProfileView->AddText(paths[i]);
			mpProfileView->AddText(_T(">"));
		}
		ProfileHasBeenModified();	
	}
	includeFileDialog->Destroy();
}

/**
 * Event handler triggered by File->New Profile
 * @param WXUNUSED( event ) 
 */
void ProfileToolFrame::OnNewProfile(wxCommandEvent& WXUNUSED(event))
{
	if (mpProfileView->GetNeedSaving())
		if (-1 == ProfileNeedSaving())
			return;
	
	ClearProfile();
}

// Triggered from the editor's context menu, it'll pull the text out
// of < > brackets and open it in a new editor
/**
 * Event handler triggered by the profile view's "Open Include in New..."
 * context menu
 * @param WXUNUSED( event )
 */
void ProfileToolFrame::OnOpenInclude(wxCommandEvent& WXUNUSED(event))
{
	wxString currentLine = mpProfileView->GetCurLine();
	wxString tmpString = currentLine.AfterFirst('<');

	if (wxEmptyString != tmpString)
	{
		wxString includeString = tmpString.BeforeLast('>');

		// Most #include statements that Novell ships are
		// relative paths, so we'll correct that here
		if (!includeString.StartsWith(_T("/"))) 
		{
			includeString.Prepend(_T("/"));
			includeString.Prepend(Configuration::GetProfileDirectory());
		}

		includeString.Prepend(_(" "));
		includeString.Prepend(Configuration::GetEditorExecutable());
		wxProcess *proc = wxProcess::Open(includeString);
		if (NULL == proc)
		{
			wxMessageDialog *dlg = new wxMessageDialog(this, _("Could not exec!"), 
									_("Error"), 
									wxOK|wxICON_ERROR);
			dlg->ShowModal();
			dlg->Destroy();
		}
		else
		{
			proc->Detach();
		}
	}
}

/**
 * Event handler triggered by File->Preferences.  Displays the preferences,
 * and saves the configuration data
 * @param WXUNUSED( event ) 
 */
void ProfileToolFrame::OnPreferences(wxCommandEvent& WXUNUSED(event))
{
 	PreferencesDialog *prefs = new PreferencesDialog(this, 
							ID_PREFERENCES_DIALOG, 
							_("Preferences"), 
							wxPoint(40,40), 
							wxSize(800,600));

 	if (prefs->ShowModal() == wxID_OK)
	{
		// Save the preferences
		wxString newProfileDirectory = prefs->GetProfileDir();
		wxString oldProfileDirectory = Configuration::GetProfileDirectory();

		// Don't want to cause problems with the profile tree traverser
		// down the road
		if (newProfileDirectory.Last() == '/') 
			newProfileDirectory.RemoveLast();

		Configuration::SetProfileDirectory(newProfileDirectory);
		Configuration::SetParserCommand(prefs->GetParser());
		Configuration::SetTemplateText(prefs->GetTemplateText());

		Configuration::SetCommentColour(prefs->GetCommentButtonColour());
		Configuration::SetIncludeColour(prefs->GetIncludeButtonColour());
		Configuration::SetCapColour(prefs->GetCapabilityButtonColour());
		Configuration::SetPathColour(prefs->GetPathButtonColour());
		Configuration::SetPermColour(prefs->GetPermButtonColour());

		Configuration::SetCommentFont(prefs->GetCommentButtonFont());
		Configuration::SetIncludeFont(prefs->GetIncludeButtonFont());
		Configuration::SetCapabilityFont(prefs->GetCapabilityButtonFont());
		Configuration::SetPathFont(prefs->GetPathButtonFont());
		Configuration::SetPermFont(prefs->GetPermButtonFont());
		Configuration::CommitChanges();

		mpProfileView->RefreshColoursAndFonts();
		if (oldProfileDirectory != newProfileDirectory)
			RepopulateControl();
	}
	prefs->Destroy();
}

/**
 * Event handler passed up from the profile editor when something has changed
 * in the text view.
 * @param WXUNUSED( event )
 */
void ProfileToolFrame::OnProfileModified(wxStyledTextEvent& WXUNUSED(event))
{
	ProfileHasBeenModified();
}

void ProfileToolFrame::OnQuit( wxCommandEvent& WXUNUSED(event) )
{
	if (mpProfileView->GetNeedSaving())
	{
		if (ProfileNeedSaving() != -1) 
		{
			// OnClose will be triggered next, since the two events are generated
			// differently, so make sure it knows to call Destroy() immediately
			mpProfileView->SetNeedSaving(false); 
			Close(TRUE);
		}
	}
	else
	{
		Close(TRUE);
	}
}

/**
 * Event handler triggered by the "Reload profile" tree context menu
 * @param event 
 */
void ProfileToolFrame::OnReloadProfile(wxCommandEvent &event)
{
	wxTreeItemId selectedId = mpProfileTree->GetSelection();
	ProfileTreeData *data = (ProfileTreeData *) mpProfileTree->GetItemData(selectedId);
	wxString filePath = data->GetPath();

	if (mpProfileView->GetNeedSaving())
		if (ProfileNeedSaving() != 0)
			return;

	ReloadProfile(filePath);
}

/**
 * Event handler triggered by Edit->Replace
 * @param event 
 */
void ProfileToolFrame::OnReplace (wxCommandEvent& event)
{
	if (mpProfileView->GetSelectedText() != _(""))
		mReplaceData.SetFindString(mpProfileView->GetSelectedText());
	mpProfileView->SetSelection(mpProfileView->GetCurrentPos(), mpProfileView->GetCurrentPos());
	mpReplaceDialog = new wxFindReplaceDialog (this, &mReplaceData, _("Find and Replace"), wxFR_REPLACEDIALOG);
	mpReplaceDialog->Show();
}

/**
 * Event handler triggered by Edit->Save
 * @param WXUNUSED( event ) 
 */
void ProfileToolFrame::OnSave (wxCommandEvent& WXUNUSED(event))
{
	// This shouldn't be triggerable if there isn't a profile, but...
	if (mpProfileView->GetNeedSaving()) {
		wxString filename = mpProfileView->GetFileName();
		mpProfileView->SaveFile(filename);
		mpProfileView->SetSavePoint();
		mpMenuBar->Enable(ID_MENU_FILE_SAVE, false);
		mpProfileTree->SetItemTextColour(mCurrentNode, *wxBLUE);
	}
}

/**
 * Event handler triggered by Edit->SaveAs
 * @param WXUNUSED( event ) 
 */
void ProfileToolFrame::OnSaveAs (wxCommandEvent& WXUNUSED(event))
{
	wxFileDialog *dialog = new wxFileDialog(this, _("Save As"), 
				Configuration::GetProfileDirectory(),
				mpProfileView->GetFileName(), _("Any file (*)|*"), 
				wxSAVE| wxOVERWRITE_PROMPT);

	if (dialog->ShowModal() == wxID_OK)
	{
		wxString newFilename = dialog->GetPath();
		mpProfileView->SaveFile(newFilename);
		mpProfileView->SetSavePoint();
		mpProfileView->SetFileName(newFilename);
		mpProfileView->SetIsNew(false);
		mpProfileView->SetNeedSaving(false);
		// Add it to our tree
		mpProfileTree->Collapse(mRootNode);
		ProfileTreeData *data = new ProfileTreeData(newFilename);
		wxTreeItemId tmp_id = mpProfileTree->AppendItem(mRootNode, 
								wxFileName(newFilename).GetFullName(),
								-1, 
								-1, 
								data);
		mpProfileTree->SetItemTextColour(mCurrentNode, *wxBLACK);
		mCurrentNode = tmp_id;
		mpProfileTree->SetItemTextColour(mCurrentNode, *wxBLUE);
		mpProfileTree->SortChildren(mRootNode);
		mpProfileTree->SelectItem(tmp_id);
		mpProfileTree->Expand(mRootNode);
		SetStatusText(newFilename);
		SetTitle(newFilename);
	}
	dialog->Destroy();
}

/**
 * Event handler triggered by Edit->Search All
 * @param event 
 */
void ProfileToolFrame::OnSearchAllProfiles (wxCommandEvent& event)
{
	SearchAllProfilesDialog *searchDialog = new SearchAllProfilesDialog(this);
	searchDialog->SetProfileDirectory(Configuration::GetProfileDirectory());
	searchDialog->SetEditorExecutable(Configuration::GetEditorExecutable());

	if (wxSTC_APPARMOR_SEARCH_PHRASE_IN_ALL_PROFILES == event.GetId())
		searchDialog->SetSearchText(mpProfileView->GetSelectedText());
	
	searchDialog->ShowModal();
	searchDialog->Destroy();
}

/**
 * Event handler for resize events
 * @param WXUNUSED( event ) 
 */
void ProfileToolFrame::OnSize(wxSizeEvent& WXUNUSED(event))
{
	int w, h;
	GetClientSize(&w, &h);
	mpSplitterWindow->SetSize(0,0,w,h);
	mpProfileTree->Refresh();
	mpProfileTree->Update();
}

/**
 * Displays a tree context menu upon right clicks
 * @param event 
 */
void ProfileToolFrame::OnTreeContextMenu(wxTreeEvent &event)
{
	wxPoint clickPoint = event.GetPoint();
	wxTreeItemId eventItem = event.GetItem();
	if (eventItem.IsOk()) 
	{
		wxMenu eventMenu(_(""));
		eventMenu.Append(ID_TREE_CONTEXT_RELOAD, _("&Reload this profile in AppArmor"));
		eventMenu.Append(ID_TREE_CONTEXT_DELETE, _("&Delete"));
		PopupMenu(&eventMenu, clickPoint);
	}
}


/**
 * Event handler triggered by a double click on a tree item
 * @param event 
 */
void ProfileToolFrame::OnTreeSelection(wxTreeEvent& event)
{
	wxTreeItemId node = event.GetItem();
	if (node != mRootNode)
	{
		wxString filePath;
		ProfileTreeData *data = (ProfileTreeData *) mpProfileTree->GetItemData(node);
		if (NULL == data) 
		{
			// It's not a profile, it's a directory node
			mpProfileTree->Toggle(node);
		}
		else 
		{
			filePath = data->GetPath();
			// Verify that there's nothing that needs to be saved
			if (mpProfileView->GetNeedSaving()) // Yes, needs saving
			{
				if (ProfileNeedSaving() != -1) // Saved successfully
				{
					if (mCurrentNode.IsOk())
						mpProfileTree->SetItemTextColour(mCurrentNode, *wxBLACK);
					
					mCurrentNode = node;
					mpProfileTree->SetItemTextColour(mCurrentNode,*wxBLUE);
					LoadProfile(filePath, wxEmptyString);
				}
			} 
			else 
			{
				if (mCurrentNode.IsOk())
					mpProfileTree->SetItemTextColour(mCurrentNode, *wxBLACK);
				
 				mCurrentNode = node;
				mpProfileTree->SetItemTextColour(mCurrentNode,*wxBLUE);
				LoadProfile(filePath, wxEmptyString);
			}
		}
	}
}

/**
 * Takes care of brace matching
 * @param event 
 */
void ProfileToolFrame::OnUpdateUI(wxStyledTextEvent& WXUNUSED(event))
{
	// Clear any previous brace matches
	mpProfileView->BraceHighlight (wxSTC_INVALID_POSITION, wxSTC_INVALID_POSITION);
	char currentChar = mpProfileView->GetCharAt(mpProfileView->GetCurrentPos() -1 ); 

	if ( (currentChar == '}') || (currentChar == ')') || (currentChar == ']') ) {
		int currentBrace = mpProfileView->GetCurrentPos() - 1;
		int matchingBrace = mpProfileView->BraceMatch(currentBrace);

		if (matchingBrace != wxSTC_INVALID_POSITION) 
			mpProfileView->BraceHighlight(matchingBrace, currentBrace);
		else
			mpProfileView->BraceBadLight(currentBrace);
	}
}

