
// Type: LibUA.Core.MonitoredItemCreateRequest



namespace LibUA.Core
{
    public class MonitoredItemCreateRequest
    {
        public ReadValueId ItemToMonitor { get; protected set; }

        public MonitoringMode Mode { get; protected set; }

        public MonitoringParameters RequestedParameters { get; protected set; }

        public MonitoredItemCreateRequest(
          ReadValueId ItemToMonitor,
          MonitoringMode Mode,
          MonitoringParameters RequestedParameters)
        {
            this.ItemToMonitor = ItemToMonitor;
            this.Mode = Mode;
            this.RequestedParameters = RequestedParameters;
        }
    }
}
