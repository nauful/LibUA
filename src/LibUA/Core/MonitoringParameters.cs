using System;

namespace LibUA
{
    namespace Core
    {
        public class MonitoringParameters
        {
            public UInt32 ClientHandle { get; protected set; }
            public double SamplingInterval { get; protected set; }
            public MonitoringFilter Filter { get; protected set; }
            public UInt32 QueueSize { get; protected set; }
            public bool DiscardOldest { get; protected set; }

            public MonitoringParameters(UInt32 ClientHandle, double SamplingInterval, MonitoringFilter Filter, UInt32 QueueSize, bool DiscardOldest)
            {
                this.ClientHandle = ClientHandle;
                this.SamplingInterval = SamplingInterval;
                this.Filter = Filter;
                this.QueueSize = QueueSize;
                this.DiscardOldest = DiscardOldest;
            }
        }
    }
}
