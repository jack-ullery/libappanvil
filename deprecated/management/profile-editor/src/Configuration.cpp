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

#include <wx/config.h>
#include "Configuration.h"

// Initialize all of the static variables
wxString Configuration::mProfileDirectory = wxEmptyString;
wxString Configuration::mProfileEditorExecutable = wxEmptyString;
wxString Configuration::mParserCommand = wxEmptyString;
wxString Configuration::mTemplateText = wxEmptyString;
wxColour Configuration::mCommentColour = wxColour(DEFAULT_COMMENT_COLOUR);
wxColour Configuration::mIncludeColour = wxColour(DEFAULT_INCLUDE_COLOUR);
wxColour Configuration::mCapColour = wxColour(DEFAULT_CAP_COLOUR);
wxColour Configuration::mPathColour = wxColour(DEFAULT_PATH_COLOUR);
wxColour Configuration::mPermColour = wxColour(DEFAULT_PERM_COLOUR);
wxFont Configuration::mCapabilityFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
wxFont Configuration::mCommentFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_ITALIC, wxFONTWEIGHT_NORMAL);
wxFont Configuration::mIncludeFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
wxFont Configuration::mPathFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD);
wxFont Configuration::mPermsFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL,wxFONTWEIGHT_NORMAL);
int Configuration::mWindowX;
int Configuration::mWindowY;
int Configuration::mWindowHeight;
int Configuration::mWindowWidth;
/**
 * Reads in the initial variables
 */
void Configuration::Initialize()
{
	// Read in all of the values
	mProfileEditorExecutable = wxTheApp->argv[0];
	mWindowX = wxConfig::Get()->Read(_("WindowX"), 50);
	mWindowY = wxConfig::Get()->Read(_("WindowY"), 50);
	mWindowWidth = wxConfig::Get()->Read(_("WindowWidth"), 800);
	mWindowHeight = wxConfig::Get()->Read(_("WindowHeight"), 600);
	mProfileDirectory = wxConfig::Get()->Read(_("ProfileDirectory"), Configuration::BestGuessProfileDirectory());
	mParserCommand = wxConfig::Get()->Read(_("Parser"), BestGuessParserCommand());
	mTemplateText = wxConfig::Get()->Read(_("ProfileTemplate"), wxEmptyString);	
	mCommentColour = _ReadColour(_("CommentColour"), mCommentColour);
	mIncludeColour = _ReadColour(_("IncludeColour"), mIncludeColour);
	mCapColour = _ReadColour(_("CapabilityColour"), mCapColour);
	mPathColour = _ReadColour(_("PathColour"), mPathColour);
	mPermColour = _ReadColour(_("PermissionColour"), mPermColour);
	_ReadFont(_("CommentFont"), mCommentFont);
	_ReadFont(_("IncludeFont"), mIncludeFont);
	_ReadFont(_("CapabilityFont"), mCapabilityFont);
	_ReadFont(_("PathFont"), mPathFont);
	_ReadFont(_("PermsFont"), mPermsFont);

}

/**
 * Profiles are most likely stored in either /etc/subdomain.d or
 * /etc/apparmor.d.  Stat each to see which.
 * @param void
 * @return profile directory
 */
wxString Configuration::BestGuessProfileDirectory(void)
{
	if (wxDirExists(_("/etc/apparmor.d")))
		return (_("/etc/apparmor.d"));
	else if (wxDirExists(_("/etc/subdomain.d")))
		return (_("/etc/subdomain.d"));
	else
		return (_("/"));
}

/**
 * The parser is probably apparmor_parser or
 * subdomain_parser.  If it's neither, the user
 * will need to set it manually, so return /bin/false
 * @return the path to the parser
 */
wxString Configuration::BestGuessParserCommand()
{
	if (wxFileExists(_("/sbin/apparmor_parser")))
		return _("/sbin/apparmor_parser");
	else if (wxFileExists(_("/sbin/subdomain_parser")))
		return _("/sbin/subdomain_parser");
	else 
		return _("/bin/false");
}

/**
 * Writes all of the values to disk
 * @return only true for now
 */
bool Configuration::CommitChanges()
{
	wxConfig::Get()->Write(_("ProfileDirectory"), mProfileDirectory);
	wxConfig::Get()->Write(_("Parser"), mParserCommand);
	wxConfig::Get()->Write(_("ProfileTemplate"), mTemplateText);
	_WriteColour(_("CommentColour"), mCommentColour);
	_WriteColour(_("IncludeColour"), mIncludeColour);
	_WriteColour(_("CapabilityColour"), mCapColour);
	_WriteColour(_("PathColour"), mPathColour);
	_WriteColour(_("PermissionColour"), mPermColour);
	wxConfig::Get()->Write(_("CommentFont"), mCommentFont.GetNativeFontInfoDesc());
	wxConfig::Get()->Write(_("IncludeFont"),  mIncludeFont.GetNativeFontInfoDesc());
	wxConfig::Get()->Write(_("CapabilityFont"),  mCapabilityFont.GetNativeFontInfoDesc());
	wxConfig::Get()->Write(_("PathFont"),  mPathFont.GetNativeFontInfoDesc());
	wxConfig::Get()->Write(_("PermsFont"),  mPermsFont.GetNativeFontInfoDesc());
	wxConfig::Get()->Flush();
	return true;
}

/**
 * Writes the given window settings to the configuration file.
 * This is kept separately from CommitChanges() because:
 * a) There's no reason to re-write all configuration changes on exit and
 * b) There's no reason to update the window position and size on every OnSize() event
 */
void Configuration::WriteWindowSettings(const wxPoint &pos, const wxSize& size)
{
	wxConfig::Get()->Write(_("WindowX"), pos.x);
	wxConfig::Get()->Write(_("WindowY"), pos.y);
	wxConfig::Get()->Write(_("WindowWidth"), size.GetWidth());
	wxConfig::Get()->Write(_("WindowHeight"), size.GetHeight());
	wxConfig::Get()->Flush();
}
/**
 * Reads a colour setting from the config file and translates it into
 * a wxColour.  If it can't convert the stored value, or the stored value 
 * does not exist, it will return whatever is passed as defaultColour.
 * @param key the configuration key
 * @param defaultColour a colour to return
 * @return a colour
 */
wxColour Configuration::_ReadColour(const wxString& key, const wxColour& defaultColour)
{
	wxColour ret;
	wxString tmpStr = wxConfig::Get()->Read(key, wxEmptyString);

	if (tmpStr.Length() == 6)
	{
		ret.Set(wxHexToDec(tmpStr.Mid(0,2)), // Red
			wxHexToDec(tmpStr.Mid(2,2)), // Green
			wxHexToDec(tmpStr.Mid(4,2)) // Blue
		);
	}

	if (ret.Ok())
		return ret;
	else
        	return defaultColour;
}

/**
 * Reads a font from the configuration file, and sets it as the 'font'
 * @param key configuration key
 * @param font the font to set
 */
void Configuration::_ReadFont(const wxString& key, wxFont& font)
{
	wxString tmpStr;
	if (wxConfig::Get()->Read(key, &tmpStr))
		font.SetNativeFontInfo(tmpStr);
}

/**
 * Takes a wxColour and converts it to a hex string for writing to disk.
 * @param key configuration key
 * @param colour the colour to convert
 */
void Configuration::_WriteColour(const wxString& key, const wxColour& colour)
{
	wxConfig::Get()->Write(key, wxString::Format(_T("%02x%02x%02x"),
							colour.Red(),
							colour.Green(),
							colour.Blue()));
}

