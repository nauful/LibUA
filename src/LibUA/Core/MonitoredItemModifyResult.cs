using System;

namespace LibUA
{
    namespace Core
    {
        public class MonitoredItemModifyResult
        {
            public StatusCode StatusCode { get; protected set; }
            public double RevisedSamplingInterval { get; protected set; }
            public UInt32 RevisedQueueSize { get; protected set; }
            public ExtensionObject Filter { get; protected set; }

            public MonitoredItemModifyResult(StatusCode StatusCode, double RevisedSamplingInterval, UInt32 RevisedQueueSize, ExtensionObject Filter)
            {
                this.StatusCode = StatusCode;
                this.RevisedSamplingInterval = RevisedSamplingInterval;
                this.RevisedQueueSize = RevisedQueueSize;
                this.Filter = Filter;
            }
        }
    }
}
