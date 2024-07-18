using System;

namespace LibUA
{
    namespace Core
    {
        public class ReadEventDetails
        {
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

            public SimpleAttributeOperand[] SelectClauses
            {
                get; protected set;
            }

            public ReadEventDetails(DateTime StartTime, DateTime EndTime, UInt32 NumValuesPerNode, SimpleAttributeOperand[] SelectClauses)
            {
                this.StartTime = StartTime;
                this.EndTime = EndTime;
                this.NumValuesPerNode = NumValuesPerNode;
                this.SelectClauses = SelectClauses;
            }
        }
    }
}
