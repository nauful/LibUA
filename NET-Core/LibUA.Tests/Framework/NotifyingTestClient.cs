using System.Threading;
using LibUA.Core;

namespace LibUA.Tests
{
    /// <summary>
    /// TestClient subclass that captures data change and event notifications
    /// in thread-safe collections for integration test assertions.
    /// NotifyDataChangeNotifications and NotifyEventNotifications are called
    /// on the Client's background receive thread, so all access must be thread-safe.
    /// </summary>
    public class NotifyingTestClient : TestClient
    {
        private readonly object notificationLock = new();

        // Data change notification tracking
        private int dataChangeNotificationCount;
        private readonly List<(uint SubscriptionId, uint ClientHandle, DataValue Value)> dataChangeNotifications = new();

        // Event notification tracking
        private int eventNotificationCount;
        private readonly List<(uint SubscriptionId, uint[] ClientHandles, object[][] Notifications)> eventNotifications = new();

        // Wait handle for signaling when a target notification count is reached
        private ManualResetEventSlim? dataChangeEvent;
        private int dataChangeTargetCount;

        public NotifyingTestClient(string Target, int Port, int Timeout)
            : base(Target, Port, Timeout)
        {
        }

        /// <summary>
        /// Total number of DataChangeNotification callbacks received (across all subscriptions).
        /// Each callback may contain multiple monitored items, so this counts callbacks, not individual items.
        /// </summary>
        public int DataChangeNotificationCallbackCount
        {
            get
            {
                lock (notificationLock)
                {
                    return dataChangeNotificationCount;
                }
            }
        }

        /// <summary>
        /// Total number of individual data change values received across all callbacks.
        /// </summary>
        public int TotalDataChangeValuesReceived
        {
            get
            {
                lock (notificationLock)
                {
                    return dataChangeNotifications.Count;
                }
            }
        }

        /// <summary>
        /// Snapshot copy of all received data change notifications.
        /// Each entry records the subscription ID, client handle, and DataValue.
        /// </summary>
        public List<(uint SubscriptionId, uint ClientHandle, DataValue Value)> DataChangeNotificationsSnapshot
        {
            get
            {
                lock (notificationLock)
                {
                    return new List<(uint SubscriptionId, uint ClientHandle, DataValue Value)>(dataChangeNotifications);
                }
            }
        }

        /// <summary>
        /// Total number of EventNotification callbacks received.
        /// </summary>
        public int EventNotificationCallbackCount
        {
            get
            {
                lock (notificationLock)
                {
                    return eventNotificationCount;
                }
            }
        }

        /// <summary>
        /// Snapshot copy of all received event notifications.
        /// </summary>
        public List<(uint SubscriptionId, uint[] ClientHandles, object[][] Notifications)> EventNotificationsSnapshot
        {
            get
            {
                lock (notificationLock)
                {
                    return new List<(uint SubscriptionId, uint[] ClientHandles, object[][] Notifications)>(eventNotifications);
                }
            }
        }

        /// <summary>
        /// Set a target count for data change notification callbacks.
        /// When DataChangeNotificationCallbackCount reaches this target, the wait handle is set.
        /// Must be called BEFORE connecting the client or creating subscriptions.
        /// </summary>
        public void SetDataChangeTarget(int targetCount)
        {
            lock (notificationLock)
            {
                dataChangeTargetCount = targetCount;
                dataChangeEvent = new ManualResetEventSlim(false);
            }
        }

        /// <summary>
        /// Wait for the data change notification target count to be reached.
        /// Returns true if signaled before timeout, false if timeout elapsed.
        /// </summary>
        public bool WaitForDataChangeTarget(int timeoutMs)
        {
            ManualResetEventSlim? evt;
            lock (notificationLock)
            {
                if (dataChangeNotificationCount >= dataChangeTargetCount)
                {
                    return true; // Already reached
                }
                evt = dataChangeEvent;
            }
            if (evt == null) return false;
            return evt.Wait(timeoutMs);
        }

        /// <summary>
        /// Reset all notification counters and collections for reuse across tests.
        /// </summary>
        public void ResetNotifications()
        {
            lock (notificationLock)
            {
                dataChangeNotificationCount = 0;
                dataChangeNotifications.Clear();
                eventNotificationCount = 0;
                eventNotifications.Clear();
                dataChangeTargetCount = 0;
                dataChangeEvent?.Dispose();
                dataChangeEvent = null;
            }
        }

        /// <summary>
        /// Called on the Client background thread when data change notifications are received.
        /// Thread-safe: locked on notificationLock.
        /// </summary>
        public override void NotifyDataChangeNotifications(uint subscrId, uint[] clientHandles, DataValue[] notifications)
        {
            lock (notificationLock)
            {
                dataChangeNotificationCount++;

                for (int i = 0; i < clientHandles.Length; i++)
                {
                    dataChangeNotifications.Add((subscrId, clientHandles[i], notifications[i]));
                }

                // Signal the wait handle if target is reached
                if (dataChangeEvent != null && dataChangeNotificationCount >= dataChangeTargetCount)
                {
                    dataChangeEvent.Set();
                }
            }
        }

        /// <summary>
        /// Called on the Client background thread when event notifications are received.
        /// Thread-safe: locked on notificationLock.
        /// </summary>
        public override void NotifyEventNotifications(uint subscrId, uint[] clientHandles, object[][] notifications)
        {
            lock (notificationLock)
            {
                eventNotificationCount++;
                eventNotifications.Add((subscrId, clientHandles, notifications));
            }
        }

        /// <summary>
        /// Get distinct DataValue values received as data change notifications.
        /// Uses ToString() for comparison since DataValue may not override Equals.
        /// </summary>
        public HashSet<string> GetDistinctDataChangeValues()
        {
            lock (notificationLock)
            {
                var distinctValues = new HashSet<string>();
                foreach (var record in dataChangeNotifications)
                {
                    distinctValues.Add(record.Value?.Value?.ToString() ?? "null");
                }
                return distinctValues;
            }
        }

        public new void Dispose()
        {
            base.Dispose();
            lock (notificationLock)
            {
                dataChangeEvent?.Dispose();
                dataChangeEvent = null;
            }
            GC.SuppressFinalize(this);
        }
    }
}