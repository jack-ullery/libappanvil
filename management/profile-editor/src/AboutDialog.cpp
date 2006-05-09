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

#include <wx/wfstream.h>
#include "AboutDialog.h"
#include "opensuse_logo.xpm"

IMPLEMENT_DYNAMIC_CLASS(AboutDialog, wxDialog)

BEGIN_EVENT_TABLE(AboutDialog, wxDialog)
END_EVENT_TABLE()

AboutDialog::AboutDialog()
{
}

AboutDialog::AboutDialog(wxWindow* parent, 
			wxWindowID id,
			const wxString& caption,
			const wxPoint& pos,
			const wxSize& size,
			long style)
{
    Create(parent, id, caption, pos, size, style);
}

bool AboutDialog::Create(wxWindow* parent,
			wxWindowID id,
			const wxString& caption,
			const wxPoint& pos,
			const wxSize& size,
			long style)
{
	mpLogoBitmap = NULL;
	mpVersionStaticText = NULL;
	mpCopyrightStaticText = NULL;
	mpOkButtonSizer = NULL;
	mpOkButton = NULL;

	SetExtraStyle(GetExtraStyle() | wxWS_EX_BLOCK_EVENTS);
	wxDialog::Create(parent, id, caption, pos, size, style);
	
	CreateControls();
	GetSizer()->Fit(this);
	GetSizer()->SetSizeHints(this);
	Centre();

	return true;
}

void AboutDialog::CreateControls()
{
	SetBackgroundColour(wxColour(255, 255, 255));
	wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
	SetSizer(mainSizer);
	
	wxBitmap mpLogoBitmapBitmap(opensuse_logo_xpm);
	mpLogoBitmap = new wxStaticBitmap(this, 
					wxID_ANY,
					mpLogoBitmapBitmap, 
					wxDefaultPosition,
					wxSize(223, 137),
					0);
	mainSizer->Add(mpLogoBitmap, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
	
	mpVersionStaticText = new wxStaticText(this,
					wxID_ANY,
					VERSION_STRING, 
					wxDefaultPosition,
					wxDefaultSize,
					0);
	mainSizer->Add(mpVersionStaticText, 0, wxALIGN_CENTER_HORIZONTAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpCopyrightStaticText = new wxStaticText(this, 
						wxID_ANY,
						_("(C) 2006 Novell, Inc\n"),
						wxDefaultPosition,
						wxDefaultSize,
						0);
	mainSizer->Add(mpCopyrightStaticText, 0, wxALIGN_CENTER_HORIZONTAL|wxALL|wxADJUST_MINSIZE, 5);
	
	mpLicenseTextCtrl = new wxTextCtrl(this,
					wxID_ANY,
					_T(""), 
					wxDefaultPosition,
					wxSize(400, -1),
					wxTE_MULTILINE|wxTE_READONLY);
	mpLicenseTextCtrl->SetValue(GPL_STRING);
	mainSizer->Add(mpLicenseTextCtrl, 0, wxGROW|wxALL, 5);

	mpOkButtonSizer = new wxStdDialogButtonSizer;
	
	mainSizer->Add(mpOkButtonSizer, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
	mpOkButton = new wxButton(this, 
				wxID_OK,
				_("&OK"),
				wxDefaultPosition,
				wxDefaultSize,
				0);
	mpOkButtonSizer->AddButton(mpOkButton);
	mpOkButtonSizer->Realize();
}
