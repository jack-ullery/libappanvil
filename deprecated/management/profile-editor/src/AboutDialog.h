#ifndef _ABOUTDIALOG_H_
#define _ABOUTDIALOG_H_

#define VERSION_STRING _("AppArmor Profile Editor version 0.9")
#define GPL_STRING _(" \
Portions of this software (C) 1998-2003 by Neil Hodgson <neilh@scintilla.org>\n\n \
This rest of this program is free software; you can redistribute it and/or modify \
it under the terms of the GNU General Public License as published by \
the Free Software Foundation; either version 2 of the License, or \
(at your option) any later version. \
\n\n \
This program is distributed in the hope that it will be useful, \
but WITHOUT ANY WARRANTY; without even the implied warranty of \
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the \
GNU General Public License for more details. \
\n\n \
You should have received a copy of the GNU General Public License \
along with this program; if not, write to the Free Software \
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA \
")

/**
 * The "About" dialog
 */
class AboutDialog: public wxDialog
{    
	DECLARE_DYNAMIC_CLASS(AboutDialog)
	DECLARE_EVENT_TABLE()
	
public:
	AboutDialog();
	AboutDialog(wxWindow* parent, 
			wxWindowID id = wxID_ANY,
			const wxString& caption = _T("About"), 
			const wxPoint& pos = wxDefaultPosition, 
			const wxSize& size = wxSize(400, 300), 
			long style = wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX);
	bool Create(wxWindow* parent, 
			wxWindowID id = wxID_ANY,
			const wxString& caption = _T("About"), 
			const wxPoint& pos = wxDefaultPosition, 
			const wxSize& size = wxSize(400, 300), 
			long style = wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX);
	void CreateControls();
	
private:
	wxStaticBitmap* mpLogoBitmap;
	wxStaticText* mpVersionStaticText;
	wxStaticText* mpCopyrightStaticText;
	wxStdDialogButtonSizer* mpOkButtonSizer;
	wxTextCtrl* mpLicenseTextCtrl;
	wxButton* mpOkButton;
};

#endif
// _ABOUTDIALOG_H_
