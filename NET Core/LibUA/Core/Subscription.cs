
// Type: LibUA.Core.Subscription



using System;
using System.Collections.Generic;

namespace LibUA.Core
{
    public class Subscription
    {
        public Subscription.ChangeNotificationType ChangeNotification;
        public uint SubscriptionId;
        public uint LifetimeCount;
        public uint MaxKeepAliveCount;
        public uint MaxNotificationsPerPublish;
        public uint SequenceNumber;
        public double PublishingInterval;
        public bool PublishingEnabled;
        public byte Priority;
        public DateTime PublishPreviousTime;
        public TimeSpan PublishInterval;
        public TimeSpan PublishKeepAliveInterval;
        public Dictionary<uint, MonitoredItem> MonitoredItems;

        public Subscription()
        {
            this.SubscriptionId = uint.MaxValue;
            this.PublishingEnabled = false;
            this.SequenceNumber = 1U;
            this.PublishingInterval = 0.0;
            this.LifetimeCount = 0U;
            this.MaxKeepAliveCount = 0U;
            this.MaxNotificationsPerPublish = 0U;
            this.PublishPreviousTime = DateTime.MinValue;
            this.PublishInterval = TimeSpan.Zero;
            this.PublishKeepAliveInterval = TimeSpan.Zero;
            this.Priority = 0;
            this.ChangeNotification = Subscription.ChangeNotificationType.None;
            this.MonitoredItems = new Dictionary<uint, MonitoredItem>();
        }


        public enum ChangeNotificationType
        {
            None,
            AtPublish,
            Immediate,
        }
    }
}
