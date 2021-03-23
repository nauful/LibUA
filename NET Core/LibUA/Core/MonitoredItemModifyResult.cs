
// Type: LibUA.Core.MonitoredItemModifyResult



namespace LibUA.Core
{
    public class MonitoredItemModifyResult
    {
        public StatusCode StatusCode { get; protected set; }

        public double RevisedSamplingInterval { get; protected set; }

        public uint RevisedQueueSize { get; protected set; }

        public ExtensionObject Filter { get; protected set; }

        public MonitoredItemModifyResult(
          StatusCode StatusCode,
          double RevisedSamplingInterval,
          uint RevisedQueueSize,
          ExtensionObject Filter)
        {
            this.StatusCode = StatusCode;
            this.RevisedSamplingInterval = RevisedSamplingInterval;
            this.RevisedQueueSize = RevisedQueueSize;
            this.Filter = Filter;
        }
    }
}
