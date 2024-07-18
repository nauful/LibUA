using System;

namespace LibUA
{
    namespace Core
    {
        public class HistoryReadRawDetails
        {
            public bool IsReadModified
            {
                get; protected set;
            }

            public DateTime StartTime
            {
                get; protected set;
            }

            public DateTime EndTime
            {
                get; protected set;
            }

            public UInt32 NumValuesPerNode
            {
                get; protected set;
            }

            public bool ReturnBounds
            {
                get; protected set;
            }

            public HistoryReadRawDetails(bool IsReadModified, DateTime StartTime, DateTime EndTime, UInt32 NumValuesPerNode, bool ReturnBounds)
            {
                this.IsReadModified = IsReadModified;
                this.StartTime = StartTime;
                this.EndTime = EndTime;
                this.NumValuesPerNode = NumValuesPerNode;
                this.ReturnBounds = ReturnBounds;
            }
        }
    }
}
