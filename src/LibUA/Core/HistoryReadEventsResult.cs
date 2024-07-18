namespace LibUA
{
    namespace Core
    {
        public class HistoryReadEventsResult
        {
            public struct Event
            {
                public object[] Fields;
            }

            public StatusCode StatusCode
            {
                get; protected set;
            }

            public byte[] ContinuationPoint
            {
                get; protected set;
            }

            public Event[] Events
            {
                get; protected set;
            }

            public HistoryReadEventsResult(StatusCode StatusCode, byte[] ContinuationPoint, Event[] Events)
            {
                this.StatusCode = StatusCode;
                this.ContinuationPoint = ContinuationPoint;
                this.Events = Events;
            }
        }
    }
}
