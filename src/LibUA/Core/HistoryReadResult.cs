using System;

namespace LibUA
{
    namespace Core
    {
        public class HistoryReadResult
        {
            public UInt32 StatusCode { get; protected set; }
            public byte[] ContinuationPoint { get; protected set; }
            public DataValue[] Values { get; protected set; }

            public HistoryReadResult(UInt32 StatusCode, byte[] ContinuationPoint, DataValue[] Values)
            {
                this.StatusCode = StatusCode;
                this.ContinuationPoint = ContinuationPoint;
                this.Values = Values;
            }
        }
    }
}
