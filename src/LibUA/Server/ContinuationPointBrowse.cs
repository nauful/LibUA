using LibUA.Core;

namespace LibUA
{
    namespace Server
    {
        public class ContinuationPointBrowse
        {
            public bool IsValid;
            public int Offset, MaxReferencesPerNode;
            public BrowseDescription Desc { get; protected set; }
            public ContinuationPointBrowse(BrowseDescription Desc, int MaxReferencesPerNode)
            {
                this.Desc = Desc;
                this.MaxReferencesPerNode = MaxReferencesPerNode;

                IsValid = false;
                Offset = 0;
            }
        }
    }
}
