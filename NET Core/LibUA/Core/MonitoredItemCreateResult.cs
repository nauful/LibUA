
// Type: LibUA.Core.MonitoredItemCreateResult



namespace LibUA.Core
{
    public class MonitoredItemCreateResult : MonitoredItemModifyResult
    {
        public uint MonitoredItemId { get; protected set; }

        public MonitoredItemCreateResult(
          StatusCode StatusCode,
          uint MonitoredItemId,
          double RevisedSamplingInterval,
          uint RevisedQueueSize,
          ExtensionObject Filter)
          : base(StatusCode, RevisedSamplingInterval, RevisedQueueSize, Filter)
        {
            this.MonitoredItemId = MonitoredItemId;
        }
    }
}
