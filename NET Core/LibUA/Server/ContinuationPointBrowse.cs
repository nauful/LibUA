
// Type: LibUA.Server.ContinuationPointBrowse



using LibUA.Core;

namespace LibUA.Server
{
    public class ContinuationPointBrowse
    {
        public bool IsValid;
        public int Offset;
        public int MaxReferencesPerNode;

        public BrowseDescription Desc { get; protected set; }

        public ContinuationPointBrowse(BrowseDescription Desc, int MaxReferencesPerNode)
        {
            this.Desc = Desc;
            this.MaxReferencesPerNode = MaxReferencesPerNode;
            this.IsValid = false;
            this.Offset = 0;
        }
    }
}
