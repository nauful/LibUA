using System;

namespace LibUA
{
    namespace Core
    {
        public class ReadProcessedDetails
        {
            public DateTime StartTime { get; protected set; }
            public DateTime EndTime { get; protected set; }
            public double ProcessingInterval { get; protected set; }
            public NodeId[] AggregateTypes { get; protected set; }
            public AggregateConfiguration Configuration { get; protected set; }

            public ReadProcessedDetails(DateTime StartTime, DateTime EndTime, double ProcessingInterval, NodeId[] AggregateTypes, AggregateConfiguration Configuration)
            {
                this.StartTime = StartTime;
                this.EndTime = EndTime;
                this.ProcessingInterval = ProcessingInterval;
                this.AggregateTypes = AggregateTypes;
                this.Configuration = Configuration;
            }
        }
    }
}
