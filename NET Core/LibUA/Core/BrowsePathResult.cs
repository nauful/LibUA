
// Type: LibUA.Core.BrowsePathResult



namespace LibUA.Core
{
    public class BrowsePathResult
    {
        public StatusCode StatusCode { get; protected set; }

        public BrowsePathTarget[] Targets { get; protected set; }

        public BrowsePathResult(StatusCode StatusCode, BrowsePathTarget[] Targets)
        {
            this.StatusCode = StatusCode;
            this.Targets = Targets;
        }
    }
}
