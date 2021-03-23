
// Type: LibUA.Core.HistoryReadResult



namespace LibUA.Core
{
    public class HistoryReadResult
    {
        public uint StatusCode { get; protected set; }

        public byte[] ContinuationPoint { get; protected set; }

        public DataValue[] Values { get; protected set; }

        public HistoryReadResult(uint StatusCode, byte[] ContinuationPoint, DataValue[] Values)
        {
            this.StatusCode = StatusCode;
            this.ContinuationPoint = ContinuationPoint;
            this.Values = Values;
        }
    }
}
