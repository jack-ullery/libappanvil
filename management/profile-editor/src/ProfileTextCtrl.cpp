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

#include <wx/textctrl.h>
#include <wx/textfile.h>
#include <wx/config.h>
#include "ProfileTextCtrl.h"
#include "Preferences.h"
#include "Configuration.h"

BEGIN_EVENT_TABLE(ProfileTextCtrl, wxStyledTextCtrl)
	EVT_STC_CHANGE(ID_STYLED_PROFILE_WINDOW, ProfileTextCtrl::OnModified)
END_EVENT_TABLE()

ProfileTextCtrl::ProfileTextCtrl(wxWindow *parent, wxWindowID id,
				const wxPoint &pos,
				const wxSize &size,
				long style)
		:  wxStyledTextCtrl (parent, id, pos, size, style|wxTE_WORDWRAP|wxTE_MULTILINE|wxTE_PROCESS_ENTER)
{
	mpParentWindow = parent;
	SetLexer(wxSTC_LEX_APPARMOR);
	StyleClearAll();
	RefreshColoursAndFonts();
	mNeedSaving = false;
	mIsNew = false;
}

/**
 * Loads a file from disk
 * @param filename The file to load
 * @return true on success, false on failure
 */
bool ProfileTextCtrl::LoadFile(const wxString& filename)
{
	wxTextFile file;
	wxString currentLine;

	if (!file.Open(filename))
		return false;

	mIgnoreChanges = true; // Have OnModified ignore the events from loading the file
	Clear();
	mFilename = filename;	
	wxStyledTextCtrl::LoadFile(filename);
	mIgnoreChanges = false;

	mNeedSaving = false;
	mIsNew = false;
	return true;
}

/**
 * Event handler triggered by any change in the window
 * @param event 
 */
void ProfileTextCtrl::OnModified(wxStyledTextEvent &event)
{
	if (!mIgnoreChanges)
	{
		mNeedSaving = true;
		wxPostEvent(mpParentWindow, event);	
	}
}

/**
 * Reloads the syntax colouring and fonts
 * @param  
 */
void ProfileTextCtrl::RefreshColoursAndFonts(void)
{
	wxColour yellowColour(252,253,127);
	wxFont defaultFont (10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
	wxFont commentFont = Configuration::GetCommentFont();
	wxFont includeFont = Configuration::GetIncludeFont();
	wxFont capabilityFont = Configuration::GetCapabilityFont();
	wxFont permFont = Configuration::GetPermFont();
	wxFont pathFont = Configuration::GetPathFont();

	StyleSetFont (wxSTC_STYLE_DEFAULT, defaultFont);
	StyleSetForeground (wxSTC_STYLE_DEFAULT, *wxBLACK);
	StyleSetBackground (wxSTC_STYLE_DEFAULT, *wxWHITE);
	StyleSetFont (wxSTC_APPARMOR_COMMENT, commentFont);
	StyleSetForeground (wxSTC_APPARMOR_COMMENT, Configuration::GetCommentColour());
	StyleSetBackground (wxSTC_APPARMOR_COMMENT, *wxWHITE);
	StyleSetFont (wxSTC_APPARMOR_INCLUDE, includeFont);
	StyleSetForeground (wxSTC_APPARMOR_INCLUDE, Configuration::GetIncludeColour());
	StyleSetBackground (wxSTC_APPARMOR_INCLUDE, *wxWHITE);
	StyleSetFont (wxSTC_APPARMOR_CAPABILITY, capabilityFont);
	StyleSetForeground (wxSTC_APPARMOR_CAPABILITY, Configuration::GetCapColour());
	StyleSetBackground (wxSTC_APPARMOR_CAPABILITY, *wxWHITE);
	StyleSetFont (wxSTC_APPARMOR_PATH, pathFont);
	StyleSetForeground (wxSTC_APPARMOR_PATH, Configuration::GetPathColour());
	StyleSetBackground (wxSTC_APPARMOR_PATH, *wxWHITE);
	StyleSetFont (wxSTC_APPARMOR_PERMS, permFont);
	StyleSetForeground (wxSTC_APPARMOR_PERMS, Configuration::GetPermColour());
	StyleSetBackground (wxSTC_APPARMOR_PERMS, *wxWHITE);
	StyleSetForeground (wxSTC_STYLE_BRACELIGHT, *wxBLACK);
	StyleSetBackground (wxSTC_STYLE_BRACELIGHT, yellowColour);
	StyleSetForeground (wxSTC_STYLE_BRACEBAD, *wxBLACK);
	StyleSetBackground (wxSTC_STYLE_BRACEBAD, *wxRED);
	SetCaretWidth(2);
}

