using System;

namespace LibUA
{
    namespace Core
    {
        public class BrowseResult
        {
            public UInt32 StatusCode { get; protected set; }
            public byte[] ContinuationPoint { get; protected set; }
            public ReferenceDescription[] Refs { get; protected set; }

            public BrowseResult(UInt32 StatusCode, byte[] ContinuationPoint, ReferenceDescription[] Refs)
            {
                this.StatusCode = StatusCode;
                this.ContinuationPoint = ContinuationPoint;
                this.Refs = Refs;
            }
        }
    }
}
