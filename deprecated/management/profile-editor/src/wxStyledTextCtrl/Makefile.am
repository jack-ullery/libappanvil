
METASOURCES = AUTO
noinst_LIBRARIES = libAppArmorStyledTextCtrl.a
libAppArmorStyledTextCtrl_a_SOURCES = AutoComplete.cxx CallTip.cxx \
		CellBuffer.cxx ContractionState.cxx DocumentAccessor.cxx Document.cxx Editor.cxx \
		ExternalLexer.cxx Indicator.cxx KeyMap.cxx KeyWords.cxx LineMarker.cxx PlatWX.cpp \
		PropSet.cxx RESearch.cxx ScintillaBase.cxx ScintillaWX.cpp stc.cpp StyleContext.cxx \
		Style.cxx UniConversion.cxx ViewStyle.cxx WindowAccessor.cxx XPM.cxx \
	LexAppArmor.cxx
noinst_HEADERS = Accessor.h AutoComplete.h CallTip.h CellBuffer.h \
	ContractionState.h DocumentAccessor.h Document.h Editor.h ExternalLexer.h Indicator.h \
	KeyMap.h KeyWords.h LineMarker.h Platform.h PlatWX.h PropSet.h RESearch.h \
	SciLexer.h ScintillaBase.h Scintilla.h ScintillaWidget.h ScintillaWX.h SString.h \
	stc_cwc_d.h stc_cwc.h stc_cw_d.h stc_cw.h stc.h StyleContext.h Style.h SVector.h \
	UniConversion.h ViewStyle.h WindowAccessor.h XPM.h

AM_CFLAGS = -DSCI_LEXER -DLINK_LEXERS -fPIC -DPIC -DWX_PRECOMP -DNO_GCC_PRAGMA \
	-D__WXGTK__ -D__WX__
AM_CXXFLAGS = -DSCI_LEXER -DLINK_LEXERS -fPIC -DPIC -DWX_PRECOMP -DNO_GCC_PRAGMA
