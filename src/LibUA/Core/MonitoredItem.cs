using System;
using System.Collections.Concurrent;

namespace LibUA
{
    namespace Core
    {
        public class MonitoredItem
        {
            // Approximate because of lockless queue
            public const int MaxQueueSize = 1024;

            public int QueueSize;

            public UInt32 MonitoredItemId;
            public ReadValueId ItemToMonitor;
            public MonitoringMode Mode;
            public MonitoringParameters Parameters;

            public ConcurrentQueue<DataValue> QueueData;
            public bool QueueOverflowed;

            public Subscription ParentSubscription;

            public ConcurrentQueue<EventNotification> QueueEvent;
            public SimpleAttributeOperand[] FilterSelectClauses
            {
                get
                {
                    if (Parameters.Filter is EventFilter eventFiler)
                    {
                        return eventFiler.SelectClauses;
                    }

                    return null;
                }
            }

            public MonitoredItem(Subscription ParentSubscription)
            {
                this.ParentSubscription = ParentSubscription;

                this.QueueData = new ConcurrentQueue<DataValue>();
                this.QueueEvent = new ConcurrentQueue<EventNotification>();

                QueueOverflowed = false;
            }
        }
    }
}
