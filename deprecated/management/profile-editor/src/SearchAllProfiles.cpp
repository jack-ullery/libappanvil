/*	AppArmor Profile Editor (C) 2006 Novell, Inc.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 * 
 */

#include "wx/wxprec.h"

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

#include <wx/dir.h>
#include <wx/ffile.h>
#include <wx/busyinfo.h>
#include <wx/process.h>
#include "SearchAllProfiles.h"

IMPLEMENT_DYNAMIC_CLASS(SearchAllProfilesDialog, wxDialog)

BEGIN_EVENT_TABLE(SearchAllProfilesDialog, wxDialog)
	EVT_BUTTON(ID_SEARCH_ALL_PROFILES_BUTTON, SearchAllProfilesDialog::OnSearch)
	EVT_LISTBOX_DCLICK(ID_SEARCH_ALL_PROFILES_LIST_BOX, SearchAllProfilesDialog::OnListBoxDClick)
END_EVENT_TABLE()

SearchAllProfilesDialog::SearchAllProfilesDialog( )
{
}

SearchAllProfilesDialog::SearchAllProfilesDialog(wxWindow* parent, 
						wxWindowID id, 
						const wxString& caption, 
						const wxPoint& pos, 
						const wxSize& size,
						long style)
{
    Create(parent, id, caption, pos, size, style);
}

bool SearchAllProfilesDialog::Create(wxWindow* parent,
					wxWindowID id,
					const wxString& caption,
					const wxPoint& pos,
					const wxSize& size,
					long style )
{
	mpSearchPhraseSizer = NULL;
	mpSearchStaticText = NULL;
	mpSearchPhraseTextCtrl = NULL;
	mpSearchButton = NULL;
	mpSearchResultsListBox = NULL;
	mpOKButtonSizer = NULL;
	mProfileDirectory = wxEmptyString;
	mEditorExecutable = wxEmptyString;
	mSearchedPhrase = wxEmptyString;

	SetExtraStyle(GetExtraStyle() | wxWS_EX_BLOCK_EVENTS);
	wxDialog::Create(parent, id, caption, pos, size, style);
	
	CreateControls();
	GetSizer()->Fit(this);
	GetSizer()->SetSizeHints(this);
	Centre();
	return true;
}

void SearchAllProfilesDialog::CreateControls()
{    
	wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
	SetSizer(mainSizer);
	
	mpSearchPhraseSizer = new wxFlexGridSizer(1, 3, 0, 0);
	mainSizer->Add(mpSearchPhraseSizer, 0, wxGROW|wxALL, 5);
	
	mpSearchStaticText = new wxStaticText(this, 
						wxID_ANY,
						_T("Search phrase:"),
						wxDefaultPosition,
						wxDefaultSize,
						0);
	mpSearchPhraseSizer->Add(mpSearchStaticText, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpSearchPhraseTextCtrl = new wxTextCtrl(this,
						wxID_ANY,
						_T(""),
						wxDefaultPosition,
						wxSize(300, -1),
						0);
	mpSearchPhraseSizer->Add(mpSearchPhraseTextCtrl, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	mpSearchButton = new wxButton(this,
					ID_SEARCH_ALL_PROFILES_BUTTON,
					_("Search"),
					wxDefaultPosition,
					wxDefaultSize,
					0);
	mpSearchPhraseSizer->Add(mpSearchButton, 0, wxALIGN_RIGHT|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	mpSearchResultsListBox = new wxListBox(this,
						ID_SEARCH_ALL_PROFILES_LIST_BOX,
						wxDefaultPosition,
						wxSize(-1, 200),
						0,
						NULL,
						wxLB_SINGLE);
	mainSizer->Add(mpSearchResultsListBox, 0, wxGROW|wxALL, 5);
	
	mpOKButtonSizer = new wxStdDialogButtonSizer;
	mainSizer->Add(mpOKButtonSizer, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
	wxButton* okButton = new wxButton(this,
					wxID_CANCEL,
					_("&Cancel"),
					wxDefaultPosition,
					wxDefaultSize, 0);
	mpOKButtonSizer->AddButton(okButton);
	mpOKButtonSizer->Realize();
}

/**
 * Event handler triggered by the Search button
 * @param WXUNUSED( event ) 
 */
void SearchAllProfilesDialog::OnSearch(wxCommandEvent& WXUNUSED(event))
{
	mpSearchButton->Disable();
	mpSearchResultsListBox->Clear();
	mSearchedPhrase = mpSearchPhraseTextCtrl->GetValue();
	DoSearch(mSearchedPhrase);
	mpSearchButton->Enable();
}

/**
 * Calls the directory traverser 
 * @param searchString 
 */
void SearchAllProfilesDialog::DoSearch(const wxString& searchString)
{
	if (mProfileDirectory != wxEmptyString)
	{
		wxBusyInfo wait(_("Searching..."));
		wxTheApp->Yield(); // Needed to repaint the busy window
		SearchAllProfilesTraverser traverser(searchString, mpSearchResultsListBox);
		wxDir dir (mProfileDirectory);
		dir.Traverse(traverser,wxEmptyString);
	}
}

/**
 * A user has double clicked on a search result
 * @param event 
 */
void SearchAllProfilesDialog::OnListBoxDClick (wxCommandEvent& event)
{
	wxString execString = mEditorExecutable;
	execString.Append(_T(" "));
	execString.Append(event.GetString());
	execString.Append(_T(" \""));
	execString.Append(mSearchedPhrase);
	execString.Append(_T("\""));
	wxProcess *proc = wxProcess::Open(execString);
	if (proc == NULL)
	{
		wxMessageDialog *dlg = new wxMessageDialog(this, _("Could not exec!"), _("Error"), 
								wxOK|wxICON_ERROR);
		dlg->ShowModal();
		dlg->Destroy();
	}
	else
	{
		proc->Detach();
	}


}


