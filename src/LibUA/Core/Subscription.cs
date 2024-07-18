using System;
using System.Collections.Generic;

namespace LibUA
{
    namespace Core
    {
        public class Subscription
        {
            public enum ChangeNotificationType
            {
                // Only publish keep-alive
                None = 0,
                // Notification with next publication cycle
                AtPublish,
                // Notification with forced publish cycle interval = 0
                Immediate,
            };

            public ChangeNotificationType ChangeNotification;

            public UInt32 SubscriptionId, LifetimeCount, MaxKeepAliveCount, MaxNotificationsPerPublish;
            public UInt32 SequenceNumber;

            public double PublishingInterval;
            public bool PublishingEnabled;
            public byte Priority;

            public DateTime PublishPreviousTime;
            public TimeSpan PublishInterval, PublishKeepAliveInterval;

            public Dictionary<UInt32, MonitoredItem> MonitoredItems;

            public Subscription()
            {
                SubscriptionId = UInt32.MaxValue;
                PublishingEnabled = false;
                SequenceNumber = 1;

                PublishingInterval = 0;
                LifetimeCount = 0;
                MaxKeepAliveCount = 0;
                MaxNotificationsPerPublish = 0;

                PublishPreviousTime = DateTime.MinValue;
                PublishInterval = TimeSpan.Zero;
                PublishKeepAliveInterval = TimeSpan.Zero;

                Priority = 0;

                ChangeNotification = ChangeNotificationType.None;
                MonitoredItems = new Dictionary<uint, MonitoredItem>();
            }
        }
    }
}
