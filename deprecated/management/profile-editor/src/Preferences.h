#ifndef PREFERENCES_H
#define PREFERENCES_H

#include <wx/notebook.h>

#define CONFIG_NAME "AppArmorProfileEditor"
#define DEFAULT_COMMENT_COLOUR_R 31
#define DEFAULT_COMMENT_COLOUR_G 31
#define DEFAULT_COMMENT_COLOUR_B 210
#define DEFAULT_INCLUDE_COLOUR_R 56
#define DEFAULT_INCLUDE_COLOUR_G 136
#define DEFAULT_INCLUDE_COLOUR_B 31
#define DEFAULT_CAP_COLOUR_R 229
#define DEFAULT_CAP_COLOUR_G 33
#define DEFAULT_CAP_COLOUR_B 204
#define DEFAULT_PATH_COLOUR_R 1
#define DEFAULT_PATH_COLOUR_G 1
#define DEFAULT_PATH_COLOUR_B 1
#define DEFAULT_PERM_COLOUR_R 160
#define DEFAULT_PERM_COLOUR_G 32
#define DEFAULT_PERM_COLOUR_B 240

enum
{
	ID_COMMENT_COLOUR_BUTTON,
	ID_PERMS_COLOUR_BUTTON,
	ID_INCLUDES_COLOUR_BUTTON,
	ID_CAPABILITIES_COLOUR_BUTTON,
	ID_PATHS_COLOUR_BUTTON,
	ID_COMMENT_FONT_BUTTON,
	ID_PERMS_FONT_BUTTON,
	ID_INCLUDES_FONT_BUTTON,
	ID_CAPABILITIES_FONT_BUTTON,
	ID_PATHS_FONT_BUTTON,
	ID_PREFERENCES_NOTEBOOK,
};

/**
 * The preferences dialog
 */
class PreferencesDialog: public wxDialog
{    
	DECLARE_DYNAMIC_CLASS( PreferencesDialog )
	DECLARE_EVENT_TABLE()

	public:

		PreferencesDialog();
		PreferencesDialog(wxWindow* parent, 
				wxWindowID id, 
				const wxString& caption = _("Preferences"), 
				const wxPoint& pos = wxDefaultPosition, 
				const wxSize& size = wxSize(400, 300), 
				long style = wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX);
		bool Create(wxWindow* parent, 
				wxWindowID, 
				const wxString& caption = _("Preferences"), 
				const wxPoint& pos = wxDefaultPosition, 
				const wxSize& size = wxSize(400, 300), 
				long style = wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX );
		void CreateControls();
		wxString BestGuessProfileDirectory ();
		wxString BestGuessParserCommand ();
		
		// Event handlers
		void OnColourButton(wxCommandEvent &event);
		void OnFontButton (wxCommandEvent &event);

		// Various accessor functions so we can save the data
		wxColour GetCommentButtonColour(void) { return mpCommentsButton->GetBackgroundColour(); }
		wxColour GetIncludeButtonColour(void) { return mpIncludesButton->GetBackgroundColour(); }
		wxColour GetCapabilityButtonColour(void) { return mpCapabilitiesButton->GetBackgroundColour(); }
		wxColour GetPathButtonColour(void) { return mpPathsButton->GetBackgroundColour(); }
		wxColour GetPermButtonColour(void) { return mpPermsButton->GetBackgroundColour(); }
		wxFont GetCommentButtonFont(void) { return mpCommentsFontButton->GetFont(); }
		wxFont GetIncludeButtonFont(void) { return mpIncludesFontButton->GetFont(); }
		wxFont GetPathButtonFont(void) { return mpPathsFontButton->GetFont(); }
		wxFont GetCapabilityButtonFont(void) { return mpCapabilitiesFontButton->GetFont(); }
		wxFont GetPermButtonFont(void) { return mpPermsFontButton->GetFont(); }
		wxString GetProfileDir(void) { return mpProfileDir->GetValue(); }
		wxString GetParser(void) { return mpParserCommand->GetValue(); }
		wxString GetTemplateText(void) { return mpTemplateTextCtrl->GetText(); }
	private:
		wxNotebook*	mpPrefsNotebook;
		wxTextCtrl*	mpProfileDir;
		wxTextCtrl*	mpParserCommand;
		ProfileTextCtrl* mpTemplateTextCtrl;
		wxButton*	mpCommentsButton;
		wxButton* 	mpIncludesButton;
		wxButton* 	mpPermsButton;
		wxButton* 	mpCapabilitiesButton;
		wxButton* 	mpPathsButton;
		wxButton* 	mpCommentsFontButton;
		wxButton* 	mpIncludesFontButton;
		wxButton* 	mpCapabilitiesFontButton;
		wxButton* 	mpPathsFontButton;
		wxButton* 	mpPermsFontButton;
};

#endif


