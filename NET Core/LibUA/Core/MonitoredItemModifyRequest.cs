
// Type: LibUA.Core.MonitoredItemModifyRequest



namespace LibUA.Core
{
    public class MonitoredItemModifyRequest
    {
        public uint MonitoredItemId { get; protected set; }

        public MonitoringParameters Parameters { get; protected set; }

        public MonitoredItemModifyRequest(uint MonitoredItemId, MonitoringParameters Parameters)
        {
            this.MonitoredItemId = MonitoredItemId;
            this.Parameters = Parameters;
        }
    }
}
