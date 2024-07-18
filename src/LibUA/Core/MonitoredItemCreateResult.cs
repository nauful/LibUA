using System;

namespace LibUA
{
    namespace Core
    {
        public class MonitoredItemCreateResult : MonitoredItemModifyResult
        {
            public UInt32 MonitoredItemId { get; protected set; }

            public MonitoredItemCreateResult(StatusCode StatusCode, UInt32 MonitoredItemId, double RevisedSamplingInterval, UInt32 RevisedQueueSize, ExtensionObject Filter)
                : base(StatusCode, RevisedSamplingInterval, RevisedQueueSize, Filter)
            {
                this.MonitoredItemId = MonitoredItemId;
            }
        }
    }
}
