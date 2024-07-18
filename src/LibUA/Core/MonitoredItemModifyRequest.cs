using System;

namespace LibUA
{
    namespace Core
    {
        public class MonitoredItemModifyRequest
        {
            public UInt32 MonitoredItemId { get; protected set; }
            public MonitoringParameters Parameters { get; protected set; }

            public MonitoredItemModifyRequest(UInt32 MonitoredItemId, MonitoringParameters Parameters)
            {
                this.MonitoredItemId = MonitoredItemId;
                this.Parameters = Parameters;
            }
        }
    }
}
