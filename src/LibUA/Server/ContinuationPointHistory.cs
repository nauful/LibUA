using LibUA.Core;

namespace LibUA
{
    namespace Server
    {
        public class ContinuationPointHistory
        {
            public bool IsValid;
            public int Offset;
            public object Details;
            public TimestampsToReturn ReturnTimes;
            public HistoryReadValueId ReadId;

            public ContinuationPointHistory(object Details, TimestampsToReturn ReturnTimes, HistoryReadValueId ReadId)
            {
                this.Details = Details;
                this.ReturnTimes = ReturnTimes;
                this.ReadId = ReadId;

                IsValid = false;
                Offset = 0;
            }
        }
    }
}
