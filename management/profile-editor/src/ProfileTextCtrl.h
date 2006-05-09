#ifndef PROFILE_TEXT_CTRL_H
#define PROFILE_TEXT_CTRL_H

#include "wxStyledTextCtrl/stc.h"

#define ID_STYLED_PROFILE_WINDOW 13082

/**
 * The syntax highlighting text control
 */
class ProfileTextCtrl : public wxStyledTextCtrl
{

public:
		ProfileTextCtrl (wxWindow *parent, 
				wxWindowID id = wxID_ANY,
				const wxPoint &pos = wxDefaultPosition,
				const wxSize &size = wxDefaultSize,
				long style = wxSUNKEN_BORDER | wxVSCROLL);

		bool LoadFile(const wxString &filename);
		void ProcessLine(const wxString &currentLine);
		void RefreshColoursAndFonts();

		void OnModified(wxStyledTextEvent &event);
		void OnReturnKey(wxCommandEvent& event);

		bool GetNeedSaving() { return mNeedSaving; }
		void SetNeedSaving(bool status) { mNeedSaving = status; }	
		wxString GetFileName() { return mFilename; }
		void SetFileName(wxString fileName) { mFilename = fileName; }
		void SetIsNew(bool status) { mIsNew = status; }
		bool GetIsNew() { return mIsNew; }
		void SetIgnoreChanges(bool value) { mIgnoreChanges = value; }
private:
		wxWindow *mpParentWindow;
		wxString mFilename;
		bool mNeedSaving;
		bool mIsNew;
		bool mIgnoreChanges;
		DECLARE_EVENT_TABLE()
};

#endif
