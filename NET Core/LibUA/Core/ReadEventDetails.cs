
// Type: LibUA.Core.ReadEventDetails



using System;

namespace LibUA.Core
{
    public class ReadEventDetails
    {
        public DateTime StartTime { get; protected set; }

        public DateTime EndTime { get; protected set; }

        public uint NumValuesPerNode { get; protected set; }

        public SimpleAttributeOperand[] SelectClauses { get; protected set; }

        public ReadEventDetails(
          DateTime StartTime,
          DateTime EndTime,
          uint NumValuesPerNode,
          SimpleAttributeOperand[] SelectClauses)
        {
            this.StartTime = StartTime;
            this.EndTime = EndTime;
            this.NumValuesPerNode = NumValuesPerNode;
            this.SelectClauses = SelectClauses;
        }
    }
}
