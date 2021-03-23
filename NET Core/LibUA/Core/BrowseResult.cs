
// Type: LibUA.Core.BrowseResult



namespace LibUA.Core
{
    public class BrowseResult
    {
        public uint StatusCode { get; protected set; }

        public byte[] ContinuationPoint { get; protected set; }

        public ReferenceDescription[] Refs { get; protected set; }

        public BrowseResult(uint StatusCode, byte[] ContinuationPoint, ReferenceDescription[] Refs)
        {
            this.StatusCode = StatusCode;
            this.ContinuationPoint = ContinuationPoint;
            this.Refs = Refs;
        }
    }
}
