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

#include <wx/propdlg.h>
#include <wx/config.h>
#include <wx/colordlg.h>
#include <wx/fontdlg.h>

#include "Configuration.h"
#include "ProfileTextCtrl.h"
#include "Preferences.h"

IMPLEMENT_DYNAMIC_CLASS(PreferencesDialog, wxDialog)

BEGIN_EVENT_TABLE(PreferencesDialog, wxDialog)
	EVT_BUTTON(ID_COMMENT_COLOUR_BUTTON, PreferencesDialog::OnColourButton)
	EVT_BUTTON(ID_INCLUDES_COLOUR_BUTTON, PreferencesDialog::OnColourButton)
	EVT_BUTTON(ID_PERMS_COLOUR_BUTTON, PreferencesDialog::OnColourButton)
	EVT_BUTTON(ID_CAPABILITIES_COLOUR_BUTTON, PreferencesDialog::OnColourButton)
	EVT_BUTTON(ID_PATHS_COLOUR_BUTTON, PreferencesDialog::OnColourButton)
	EVT_BUTTON(ID_COMMENT_FONT_BUTTON, PreferencesDialog::OnFontButton)
	EVT_BUTTON(ID_INCLUDES_FONT_BUTTON, PreferencesDialog::OnFontButton)
	EVT_BUTTON(ID_CAPABILITIES_FONT_BUTTON, PreferencesDialog::OnFontButton)
	EVT_BUTTON(ID_PATHS_FONT_BUTTON, PreferencesDialog::OnFontButton)
	EVT_BUTTON(ID_PERMS_FONT_BUTTON, PreferencesDialog::OnFontButton)
END_EVENT_TABLE()

PreferencesDialog::PreferencesDialog( )
{
}

PreferencesDialog::PreferencesDialog(wxWindow* parent, 
					wxWindowID id, 
					const wxString& caption, 
					const wxPoint& pos, 
					const wxSize& size,
					long style)
{
    Create(parent, id, caption, pos, size, style);
}

bool PreferencesDialog::Create(wxWindow* parent,
				wxWindowID id,
				const wxString& caption,
				const wxPoint& pos,
				const wxSize& size,
				long style)
{
	mpPrefsNotebook = NULL;
	mpProfileDir = NULL;
	mpParserCommand = NULL;
	mpTemplateTextCtrl = NULL;
	mpCommentsButton = NULL;
	mpIncludesButton = NULL;
	mpPermsButton = NULL;
	mpCapabilitiesButton = NULL;
	mpPathsButton = NULL;
	mpCommentsFontButton = NULL;
	mpIncludesFontButton = NULL;
	mpCapabilitiesFontButton = NULL;
	mpPathsFontButton = NULL;
	
	
	SetExtraStyle(GetExtraStyle()|wxWS_EX_BLOCK_EVENTS);
	wxDialog::Create( parent, id, caption, pos, size, style );
	
	CreateControls();
	GetSizer()->Fit(this);
	GetSizer()->SetSizeHints(this);
	Centre();
	
	return true;
}

void PreferencesDialog::CreateControls()
{    
	wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
	SetSizer(mainSizer);
	
	mpPrefsNotebook = new wxNotebook(this, ID_PREFERENCES_NOTEBOOK, wxDefaultPosition, wxDefaultSize, wxNB_TOP );
	
	// The paths pane
	wxPanel* pathsPanel = new wxPanel( mpPrefsNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxSUNKEN_BORDER|wxTAB_TRAVERSAL );
	wxGridSizer* prefsGridSizer = new wxGridSizer(2, 2, 0, 0);
	pathsPanel->SetSizer(prefsGridSizer);
	
	wxStaticText* profileDirectoryText = new wxStaticText( pathsPanel, wxID_ANY, _("Profile Directory:"), wxDefaultPosition, wxDefaultSize, 0 );
	prefsGridSizer->Add(profileDirectoryText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpProfileDir = new wxTextCtrl( pathsPanel, wxID_ANY, Configuration::GetProfileDirectory(), wxDefaultPosition, wxSize(200, -1), 0 );
	prefsGridSizer->Add(mpProfileDir, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	wxStaticText* parserCommandText = new wxStaticText( pathsPanel, wxID_ANY, _("Path to apparmor_parser:"), wxDefaultPosition, wxDefaultSize, 0 );
	prefsGridSizer->Add(parserCommandText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpParserCommand = new wxTextCtrl( pathsPanel, wxID_ANY, Configuration::GetParserCommand(), wxDefaultPosition, wxSize(200, -1), 0 );
	prefsGridSizer->Add(mpParserCommand, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	mpPrefsNotebook->AddPage(pathsPanel, _("Paths"));
	
	// The colours pane //
	wxPanel* coloursPanel = new wxPanel( mpPrefsNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxSUNKEN_BORDER|wxTAB_TRAVERSAL );
	wxBoxSizer* colorFontBoxSizer = new wxBoxSizer(wxHORIZONTAL);
	coloursPanel->SetSizer(colorFontBoxSizer);
	
	wxStaticBox* colourBoxSizer = new wxStaticBox(coloursPanel, wxID_ANY, _("Colours"));
	wxStaticBoxSizer* colourStaticBoxSizer = new wxStaticBoxSizer(colourBoxSizer, wxVERTICAL);
	colorFontBoxSizer->Add(colourStaticBoxSizer, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5);
	wxGridSizer* colourSubSizer = new wxGridSizer(4, 2, 0, 0);
	colourStaticBoxSizer->Add(colourSubSizer, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
	wxStaticText* commentsText = new wxStaticText( coloursPanel, wxID_STATIC, _("Comments"), wxDefaultPosition, wxDefaultSize, 0 );
	colourSubSizer->Add(commentsText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpCommentsButton = new wxButton( coloursPanel, ID_COMMENT_COLOUR_BUTTON, _T(""), wxDefaultPosition, wxDefaultSize, 0 );
	mpCommentsButton->SetBackgroundColour(Configuration::GetCommentColour());
	colourSubSizer->Add(mpCommentsButton, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	wxStaticText* includesText = new wxStaticText( coloursPanel, wxID_STATIC, _("Includes"), wxDefaultPosition, wxDefaultSize, 0 );
	colourSubSizer->Add(includesText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpIncludesButton = new wxButton( coloursPanel, ID_INCLUDES_COLOUR_BUTTON, _T(""), wxDefaultPosition, wxDefaultSize, 0 );
	colourSubSizer->Add(mpIncludesButton, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	mpIncludesButton->SetBackgroundColour(Configuration::GetIncludeColour());

	wxStaticText* capabilitiesText = new wxStaticText( coloursPanel, wxID_STATIC, _("Capabilities"), wxDefaultPosition, wxDefaultSize, 0 );
	colourSubSizer->Add(capabilitiesText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpCapabilitiesButton = new wxButton( coloursPanel, ID_CAPABILITIES_COLOUR_BUTTON, _T(""), wxDefaultPosition, wxDefaultSize, 0 );
	colourSubSizer->Add(mpCapabilitiesButton, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	mpCapabilitiesButton->SetBackgroundColour(Configuration::GetCapColour());

	wxStaticText* pathsText = new wxStaticText( coloursPanel, wxID_STATIC, _("Paths"), wxDefaultPosition, wxDefaultSize, 0 );
	colourSubSizer->Add(pathsText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpPathsButton = new wxButton( coloursPanel, ID_PATHS_COLOUR_BUTTON, _T(""), wxDefaultPosition, wxDefaultSize, 0 );
	mpPathsButton->SetBackgroundColour(Configuration::GetPathColour());
	colourSubSizer->Add(mpPathsButton, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	wxStaticText* permsText = new wxStaticText( coloursPanel, wxID_STATIC, _("Permissions"), wxDefaultPosition, wxDefaultSize, 0 );
	colourSubSizer->Add(permsText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);

	mpPermsButton = new wxButton( coloursPanel, ID_PERMS_COLOUR_BUTTON, _T(""), wxDefaultPosition, wxDefaultSize, 0 );
	mpPermsButton->SetBackgroundColour(Configuration::GetPermColour());
	colourSubSizer->Add(mpPermsButton, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

	// Fonts pane //
	wxStaticBox* fontSubSizer = new wxStaticBox(coloursPanel, wxID_ANY, _("Fonts"));
	wxStaticBoxSizer* fontBoxSizer = new wxStaticBoxSizer(fontSubSizer, wxVERTICAL);
	colorFontBoxSizer->Add(fontBoxSizer, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5);
	wxGridSizer* fontsGridSizer = new wxGridSizer(4, 2, 0, 0);
	fontBoxSizer->Add(fontsGridSizer, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
	wxStaticText* commentFontText = new wxStaticText( coloursPanel, wxID_STATIC, _("Comments"), wxDefaultPosition, wxDefaultSize, 0 );
	fontsGridSizer->Add(commentFontText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpCommentsFontButton = new wxButton( coloursPanel, ID_COMMENT_FONT_BUTTON, _("ABCdef"), wxDefaultPosition, wxDefaultSize, 0 );
	mpCommentsFontButton->SetFont(Configuration::GetCommentFont());
	fontsGridSizer->Add(mpCommentsFontButton, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	wxStaticText* includesFontText = new wxStaticText( coloursPanel, wxID_STATIC, _("Includes"), wxDefaultPosition, wxDefaultSize, 0 );
	fontsGridSizer->Add(includesFontText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpIncludesFontButton = new wxButton( coloursPanel, ID_INCLUDES_FONT_BUTTON, _("ABCdef"), wxDefaultPosition, wxDefaultSize, 0 );
	mpIncludesFontButton->SetFont(Configuration::GetIncludeFont());
	fontsGridSizer->Add(mpIncludesFontButton, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	wxStaticText* capabilitiesFontText = new wxStaticText( coloursPanel, wxID_STATIC, _("Capabilities"), wxDefaultPosition, wxDefaultSize, 0 );
	fontsGridSizer->Add(capabilitiesFontText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpCapabilitiesFontButton = new wxButton( coloursPanel, ID_CAPABILITIES_FONT_BUTTON, _("ABCdef"), wxDefaultPosition, wxDefaultSize, 0 );
	mpCapabilitiesFontButton->SetFont(Configuration::GetCapabilityFont());
	fontsGridSizer->Add(mpCapabilitiesFontButton, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	wxStaticText* pathsFontText = new wxStaticText( coloursPanel, wxID_STATIC, _("Paths"), wxDefaultPosition, wxDefaultSize, 0 );
	fontsGridSizer->Add(pathsFontText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpPathsFontButton = new wxButton( coloursPanel, ID_PATHS_FONT_BUTTON, _("ABCdef"), wxDefaultPosition, wxDefaultSize, 0 );
	mpPathsFontButton->SetFont(Configuration::GetPathFont());
	fontsGridSizer->Add(mpPathsFontButton, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	
	wxStaticText* permsFontText = new wxStaticText( coloursPanel, wxID_STATIC, _("Permissions"), wxDefaultPosition, wxDefaultSize, 0 );
	fontsGridSizer->Add(permsFontText, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpPermsFontButton = new wxButton( coloursPanel, ID_PERMS_FONT_BUTTON, _("ABCdef"), wxDefaultPosition, wxDefaultSize, 0 );
	mpPermsFontButton->SetFont(Configuration::GetPermFont());
	fontsGridSizer->Add(mpPermsFontButton, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
	mpPrefsNotebook->AddPage(coloursPanel, _("Colours & Fonts"));

	// Templates pane //	
	mpTemplateTextCtrl = new ProfileTextCtrl (mpPrefsNotebook, wxID_ANY, wxDefaultPosition, wxDefaultSize);
	mpTemplateTextCtrl->SetText(Configuration::GetTemplateText());
	mpPrefsNotebook->AddPage(mpTemplateTextCtrl, _("New Profile Template"));
	mainSizer->Add(mpPrefsNotebook, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
	wxBoxSizer* buttonBoxSizer = new wxBoxSizer(wxHORIZONTAL);
	mainSizer->Add(buttonBoxSizer, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
	
	wxStdDialogButtonSizer* buttonSizer = new wxStdDialogButtonSizer;
	buttonBoxSizer->Add(buttonSizer, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5);
	wxButton* okButton = new wxButton( this, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
	buttonSizer->AddButton(okButton);

	wxButton* cancelButton = new wxButton( this, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
	buttonSizer->AddButton(cancelButton);	
	buttonSizer->Realize();
}

void PreferencesDialog::OnColourButton(wxCommandEvent &event)
{	
	wxColourData currentData;
	switch (event.GetId())
	{
		case ID_COMMENT_COLOUR_BUTTON:
			currentData.SetColour(mpCommentsButton->GetBackgroundColour());
			break;
		case ID_INCLUDES_COLOUR_BUTTON:
			currentData.SetColour(mpIncludesButton->GetBackgroundColour());
			break;
		case ID_CAPABILITIES_COLOUR_BUTTON:
			currentData.SetColour(mpCapabilitiesButton->GetBackgroundColour());
			break;
		case ID_PATHS_COLOUR_BUTTON:
			currentData.SetColour(mpPathsButton->GetBackgroundColour());
			break;
		case ID_PERMS_COLOUR_BUTTON:
			currentData.SetColour(mpPermsButton->GetBackgroundColour());
			break;
		default:
			currentData.SetColour(*wxWHITE);
			break;
	}
	wxColourDialog *colourPicker = new wxColourDialog(this, &currentData);
	if (colourPicker->ShowModal() == wxID_OK)
	{
		currentData = colourPicker->GetColourData();
		wxColour currentColour = currentData.GetColour();
		switch (event.GetId())
		{
			case ID_COMMENT_COLOUR_BUTTON:
		 		mpCommentsButton->SetBackgroundColour(currentColour);
				break;
			case ID_INCLUDES_COLOUR_BUTTON:	
		 		mpIncludesButton->SetBackgroundColour(currentColour);
				break;
			case ID_CAPABILITIES_COLOUR_BUTTON:
 				mpCapabilitiesButton->SetBackgroundColour(currentColour);
				break;
			case ID_PATHS_COLOUR_BUTTON:
		 		mpPathsButton->SetBackgroundColour(currentColour);
				break;
			case ID_PERMS_COLOUR_BUTTON:
				mpPermsButton->SetBackgroundColour(currentColour);
				break;
			default:
				break;
		}
	}
	colourPicker->Destroy();
}
void PreferencesDialog::OnFontButton(wxCommandEvent &event)
{

	wxFontData fontData;
	switch (event.GetId())
	{
		case ID_COMMENT_FONT_BUTTON:
			fontData.SetInitialFont(mpCommentsFontButton->GetFont());
			break;
		case ID_INCLUDES_FONT_BUTTON:
			fontData.SetInitialFont(mpIncludesFontButton->GetFont());
			break;
		case ID_CAPABILITIES_FONT_BUTTON:
			fontData.SetInitialFont(mpCapabilitiesFontButton->GetFont());
			break;
		case ID_PATHS_FONT_BUTTON:
			fontData.SetInitialFont(mpPathsFontButton->GetFont());
			break;
		case ID_PERMS_FONT_BUTTON:
			fontData.SetInitialFont(mpPermsFontButton->GetFont());
			break;
		default:
			break;
	}
	wxFontDialog *fontDialog = new wxFontDialog(this, fontData);
	if (fontDialog->ShowModal() == wxID_OK)
	{
 		fontData = fontDialog->GetFontData();
 		wxFont newFont = fontData.GetChosenFont();
		// Write it back to disk
		switch (event.GetId())
		{
			case ID_COMMENT_FONT_BUTTON:
		 		mpCommentsFontButton->SetFont(newFont);
				break;
			case ID_INCLUDES_FONT_BUTTON:	
		 		mpIncludesFontButton->SetFont(newFont);
				break;
			case ID_CAPABILITIES_FONT_BUTTON:
 				mpCapabilitiesFontButton->SetFont(newFont);
				break;
			case ID_PATHS_FONT_BUTTON:
		 		mpPathsFontButton->SetFont(newFont);
				break;
			case ID_PERMS_FONT_BUTTON:
				mpPermsFontButton->SetFont(newFont);
				break;
			default:
				break;
		}
	}
	fontDialog->Destroy();
}
