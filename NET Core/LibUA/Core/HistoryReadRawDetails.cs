
// Type: LibUA.Core.HistoryReadRawDetails



using System;

namespace LibUA.Core
{
    public class HistoryReadRawDetails
    {
        public bool IsReadModified { get; protected set; }

        public DateTime StartTime { get; protected set; }

        public DateTime EndTime { get; protected set; }

        public uint NumValuesPerNode { get; protected set; }

        public bool ReturnBounds { get; protected set; }

        public HistoryReadRawDetails(
          bool IsReadModified,
          DateTime StartTime,
          DateTime EndTime,
          uint NumValuesPerNode,
          bool ReturnBounds)
        {
            this.IsReadModified = IsReadModified;
            this.StartTime = StartTime;
            this.EndTime = EndTime;
            this.NumValuesPerNode = NumValuesPerNode;
            this.ReturnBounds = ReturnBounds;
        }
    }
}
