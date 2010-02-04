#ifndef PROFILE_DIRECTORY_TRAVERSER
#define PROFILE_DIRECTORY_TRAVERSER

/**
 * The wxDirTraverser that searches through the profile directory
 */
class ProfileDirectoryTraverser : public wxDirTraverser
{
	public:
		ProfileDirectoryTraverser(wxTreeCtrl* profileTree,
						const wxTreeItemId& startNode,
						const wxString& profileDirectory) 
							: mpProfileTree(profileTree),
							  mCurNode(startNode),
							  mOriginalNode(startNode),
							  mProfileDirectory(profileDirectory) {}

		virtual wxDirTraverseResult OnFile(const wxString& filename)
		{
			ProfileTreeData* data = new ProfileTreeData(filename);
			// OnDir isn't called when the traverser starts
			// going through the files in the top level directory,
			// so we do this to keep the profiles in the right place
			if (wxFileName(filename).GetPath() == mProfileDirectory)
				mCurNode = mOriginalNode;
 			mpProfileTree->AppendItem(mCurNode, wxFileName(filename).GetFullName(), -1, -1, data);
			return wxDIR_CONTINUE;
		}

		 virtual wxDirTraverseResult OnDir(const wxString& dirname)
		{
			mCurNode = mpProfileTree->AppendItem(mOriginalNode, wxFileName(dirname).GetName());
			return wxDIR_CONTINUE;
		}
	private:
		wxTreeCtrl*	mpProfileTree;
		wxTreeItemId	mCurNode, mOriginalNode;
		wxString 	mProfileDirectory;
};


#endif

