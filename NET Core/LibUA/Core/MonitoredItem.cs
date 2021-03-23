
// Type: LibUA.Core.MonitoredItem



using System.Collections.Concurrent;

namespace LibUA.Core
{
    public class MonitoredItem
    {
        public const int MaxQueueSize = 1024;
        public int QueueSize;
        public uint MonitoredItemId;
        public ReadValueId ItemToMonitor;
        public MonitoringMode Mode;
        public MonitoringParameters Parameters;
        public ConcurrentQueue<DataValue> QueueData;
        public bool QueueOverflowed;
        public Subscription ParentSubscription;
        public ConcurrentQueue<EventNotification> QueueEvent;
        public SimpleAttributeOperand[] FilterSelectClauses;

        public MonitoredItem(
          Subscription ParentSubscription,
          SimpleAttributeOperand[] FilterSelectClauses = null)
        {
            this.ParentSubscription = ParentSubscription;
            this.QueueData = new ConcurrentQueue<DataValue>();
            this.QueueEvent = new ConcurrentQueue<EventNotification>();
            this.FilterSelectClauses = FilterSelectClauses;
            this.QueueOverflowed = false;
        }
    }
}
