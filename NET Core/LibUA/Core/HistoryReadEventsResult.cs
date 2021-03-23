
// Type: LibUA.Core.HistoryReadEventsResult



namespace LibUA.Core
{
    public class HistoryReadEventsResult
    {
        public StatusCode StatusCode { get; protected set; }

        public byte[] ContinuationPoint { get; protected set; }

        public HistoryReadEventsResult.Event[] Events { get; protected set; }

        public HistoryReadEventsResult(
          StatusCode StatusCode,
          byte[] ContinuationPoint,
          HistoryReadEventsResult.Event[] Events)
        {
            this.StatusCode = StatusCode;
            this.ContinuationPoint = ContinuationPoint;
            this.Events = Events;
        }

        public struct Event
        {
            public object[] Fields;
        }
    }
}
