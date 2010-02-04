#ifndef _SEARCHALLPROFILESDIALOG_H_
#define _SEARCHALLPROFILESDIALOG_H_


class wxFlexGridSizer;
class wxStdDialogButtonSizer;

/**
 * A "Search All Profiles" dialog
 */
class SearchAllProfilesDialog: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS(SearchAllProfilesDialog)
    DECLARE_EVENT_TABLE()

public:
	SearchAllProfilesDialog();
	SearchAllProfilesDialog(wxWindow* parent, 
				wxWindowID id = wxID_ANY, 
				const wxString& caption = _("Search All Profiles"), 
				const wxPoint& pos = wxDefaultPosition, 
				const wxSize& size = wxSize(400, 300), 
				long style = wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX);
	
	/// Creation
	bool Create(wxWindow* parent, 
			wxWindowID id = wxID_ANY, 
			const wxString& caption = _("Search All Profiles"), 
			const wxPoint& pos = wxDefaultPosition, 
			const wxSize& size = wxSize(400, 300), 
			long style = wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX );
	void CreateControls();
	void OnSearch(wxCommandEvent& event);
	void OnListBoxDClick (wxCommandEvent& event);
	void DoSearch(const wxString& searchString);


	void SetProfileDirectory (const wxString& dir) { mProfileDirectory = dir; }
	void SetEditorExecutable (const wxString& exec) { mEditorExecutable = exec; }
	void SetSearchText (const wxString& searchString) { mpSearchPhraseTextCtrl->SetValue(searchString); }

private:
	wxFlexGridSizer*	mpSearchPhraseSizer;
	wxStaticText*		mpSearchStaticText;
	wxTextCtrl*		mpSearchPhraseTextCtrl;
	wxButton*		mpSearchButton;
	wxListBox*		mpSearchResultsListBox;
	wxStdDialogButtonSizer*	mpOKButtonSizer;
	wxString 		mProfileDirectory;
	wxString 		mEditorExecutable;
	wxString 		mSearchedPhrase;
};

/**
 * The "Search All" traverser
 */
class SearchAllProfilesTraverser : public wxDirTraverser
{
	public:
		SearchAllProfilesTraverser (const wxString& search, wxListBox *rBox) 
							: searchString(search),
							  resultsBox(rBox) {}
		virtual wxDirTraverseResult OnFile(const wxString& filename)
		{
			if (!tmpFile.Open(filename))
				return wxDIR_CONTINUE;

			if (!tmpFile.ReadAll(&tmpString))
				return wxDIR_CONTINUE;

			if (tmpString.Find(searchString) != -1)
				resultsBox->Append(filename);
			tmpFile.Close();
			return wxDIR_CONTINUE;
		}

		 virtual wxDirTraverseResult OnDir(const wxString& dirname)
		{
			return wxDIR_CONTINUE;
		}
	private:
		wxString searchString;
		wxListBox *resultsBox;
		wxString tmpString;
		wxFFile tmpFile;
		
};

enum
{
	ID_SEARCH_ALL_PROFILES_BUTTON = 15599,
	ID_SEARCH_ALL_PROFILES_LIST_BOX
};

#endif
