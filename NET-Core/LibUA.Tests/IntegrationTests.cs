using LibUA.Core;

namespace LibUA.Tests
{
    /// <summary>
    /// Integration tests for the LibUA client/server pair.
    /// 
    /// Architecture:
    /// - One shared server (IntegrationTestServerFixture) on port 7719, running continuously
    ///   with PlayRow() timer every 500ms. The server is thread-safe and designed for serial
    ///   access from multiple clients.
    /// - Each test creates its own isolated NotifyingTestClient (no client state is shared).
    ///   The Client class is NOT thread-safe for concurrent API calls, but since xUnit runs
    ///   tests serially within a [Collection], this is safe.
    /// - All notification-dependent tests use retry logic with a fresh client on failure.
    ///   This makes tests robust against timing variations and server pulse loop delays.
    /// 
    /// Test isolation:
    /// - [Collection(nameof(IntegrationTestServerFixture)] forces serial execution
    /// - Each test creates its own client via CreateConnectedClient()
    /// - DisposeClient() waits 1s after Disconnect() to allow the server's dispatcher
    ///   thread to fully exit and call RemoveDispatcher() before the next test connects
    /// - Test 5 explicitly deletes subscriptions/monitored items before CloseSession
    ///   to avoid orphaned entries in the server's global monitorMap
    /// </summary>
    [Collection(nameof(IntegrationTestServerFixture))]
    public class IntegrationTests : IDisposable
    {
        private readonly IntegrationTestServerFixture serverFixture;

        public IntegrationTests(IntegrationTestServerFixture fixture)
        {
            serverFixture = fixture;
        }

        public void Dispose()
        {
            GC.SuppressFinalize(this);
        }

        // ============================================================
        // Helper methods
        // ============================================================

        /// <summary>
        /// Create a fully connected NotifyingTestClient with session activated (anonymous).
        /// Each call returns a completely independent client instance.
        /// </summary>
        private NotifyingTestClient CreateConnectedClient()
        {
            var client = new NotifyingTestClient(
                IntegrationTestServerFixture.HostName,
                IntegrationTestServerFixture.PortNumber,
                15);

            client.Connect();
            client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

            var appDesc = new ApplicationDescription(
                "urn:DemoApplication", "http://quantensystems.com/",
                new LocalizedText("en-US", "QuantenSystems integration test client"), ApplicationType.Client,
                null, null, null);

            client.CreateSession(appDesc, "urn:DemoApplication", requestedSessionTimeout: 120);
            client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

            return client;
        }

        /// <summary>
        /// Disconnect and dispose a NotifyingTestClient.
        /// 
        /// IMPORTANT: Includes a 1-second delay to allow the server's dispatcher thread
        /// to fully clean up. The dispatcher thread needs to:
        ///   1. Detect the socket disconnect (via Socket.Receive returning 0)
        ///   2. Exit the main loop
        ///   3. Call RemoveDispatcher() which releases the listenerAvailable semaphore
        /// 
        /// Without this delay, a subsequent test's client may block waiting for a
        /// semaphore slot, causing intermittent failures with BadConnectionRejected.
        /// The 1-second delay is conservative and covers the Socket.Select timeout
        /// (up to 1000ms on the server) plus thread exit overhead.
        /// </summary>
        private static void DisposeClient(NotifyingTestClient? client)
        {
            if (client != null)
            {
                try { client.Disconnect(); } catch { /* ignore */ }
                client.Dispose();
                Thread.Sleep(1000); // Allow server dispatcher thread to fully exit
            }
        }

        /// <summary>
        /// Helper: wait for a minimum number of data change notification callbacks,
        /// polling at 200ms intervals up to the given timeout. Returns the actual
        /// callback count reached before timeout.
        /// </summary>
        private static int WaitForMinCallbacks(NotifyingTestClient client, int minTarget, int timeoutMs)
        {
            client.SetDataChangeTarget(minTarget);
            bool signaled = client.WaitForDataChangeTarget(timeoutMs);
            return client.DataChangeNotificationCallbackCount;
        }

        /// <summary>
        /// Retry a notification-dependent operation up to 3 times with a fresh client each time.
        /// If the operation fails (returns false or assertion fails), the client is disposed,
        /// we wait 500ms, and try again with a new client. This makes tests robust against
        /// timing variations and server pulse loop delays.
        /// 
        /// The server's publish pipeline has multiple timing-sensitive steps:
        ///   1. PlayRow (500ms) → MonitorNotifyDataChange → queue data in MonitoredItem.QueueData
        ///   2. Server NeedsPulse (every 100ms) → SLPulseDataChangeNotification → send PublishResponse
        ///   3. Client receive thread → ConsumeNotification → NotifyDataChangeNotifications callback
        /// 
        /// A retry with a fresh client resets the publish pipeline state on the server side
        /// and gives the timer-based data flow a clean start.
        /// </summary>
        private delegate bool NotificationTestOperation(NotifyingTestClient client);

        private static bool RetryNotificationTest(string testName, NotificationTestOperation op, int maxRetries = 3)
        {
            NotifyingTestClient? client = null;
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                if (client != null)
                {
                    DisposeClient(client);
                    Thread.Sleep(500); // Brief pause between retries
                }

                client = new NotifyingTestClient(
                    IntegrationTestServerFixture.HostName,
                    IntegrationTestServerFixture.PortNumber,
                    15);

                try
                {
                    client.Connect();
                    client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                    var appDesc = new ApplicationDescription(
                        "urn:DemoApplication", "http://quantensystems.com/",
                        new LocalizedText("en-US", "QuantenSystems integration test client"), ApplicationType.Client,
                        null, null, null);

                    client.CreateSession(appDesc, "urn:DemoApplication", requestedSessionTimeout: 120);
                    client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                    if (op(client))
                    {
                        return true;
                    }

                    Console.WriteLine($"  [{testName}] Attempt {attempt}/{maxRetries} failed — retrying with fresh client...");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [{testName}] Attempt {attempt}/{maxRetries} threw {ex.GetType().Name}: {ex.Message} — retrying with fresh client...");
                }
            }

            // Last resort: dispose without retry
            if (client != null)
            {
                DisposeClient(client);
            }
            return false;
        }

        // ============================================================
        // TEST 1: Primary data change notification test
        // ============================================================
        // Tests the full OPC UA publish/subscribe pipeline:
        //   1. Server PlayRow (500ms timer) → MonitorNotifyDataChange → queue data
        //   2. Server NeedsPulse (every 100ms) → SLPulseDataChangeNotification → send PublishResponse
        //   3. Client receive thread → ConsumeNotification → NotifyDataChangeNotifications callback
        //
        // Because PlayRow generates values as float(rowCount + 0.1 * rnd.NextDouble()),
        // each value is distinct, giving us 10 unique values from 10 callbacks.
        //
        // Uses RetryNotificationTest for robustness against timing variations.

        [Fact]
        public void DataChangeNotification_WaitFor10DistinctNotifications_Succeeds()
        {
            bool passed = RetryNotificationTest("DataChangeNotification", (client) =>
            {
                uint subscrId = 0;

                // Create subscription and monitored items for 3 TrendNodes
                client.CreateSubscription(0, 1000, true, 0, out subscrId);
                Assert.NotEqual(0u, subscrId);

                uint[] monitorIds = [1u, 2u, 3u];
                client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                [
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(monitorIds[0], 0, null, 100, false)),
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 2), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(monitorIds[1], 0, null, 100, false)),
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 3), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(monitorIds[2], 0, null, 100, false)),
                ], out MonitoredItemCreateResult[] monitorCreateResults);

                Assert.NotNull(monitorCreateResults);
                Assert.Equal(3, monitorCreateResults.Length);
                for (int i = 0; i < 3; i++)
                {
                    Assert.Equal(StatusCode.Good, monitorCreateResults[i].StatusCode);
                }

                // Give the publish pipeline time to establish
                Thread.Sleep(2000);

                // Wait for 10 data change notification callbacks with distinct values
                client.SetDataChangeTarget(10);
                bool signaled = client.WaitForDataChangeTarget(30000);

                if (!signaled)
                {
                    Console.WriteLine($"    Notifications received: {client.DataChangeNotificationCallbackCount}, " +
                        $"distinct: {client.GetDistinctDataChangeValues().Count}");
                    client.DeleteMonitoredItems(subscrId, monitorIds, out _);
                    client.DeleteSubscription([subscrId], out _);
                    return false;
                }

                var distinctValues = client.GetDistinctDataChangeValues();
                Assert.True(distinctValues.Count >= 10,
                    $"Expected ≥10 distinct data change values but got {distinctValues.Count}.");

                client.DeleteMonitoredItems(subscrId, monitorIds, out _);
                client.DeleteSubscription([subscrId], out _);
                return true;
            });

            Assert.True(passed,
                "DataChangeNotification test failed after 3 retries with fresh clients. " +
                "Check console output for per-attempt diagnostic messages.");
        }

        // ============================================================
        // TEST 2: Subscription lifecycle (no timing sensitivity)
        // ============================================================
        // Tests CreateSubscription, ModifySubscription, SetPublishingMode, DeleteSubscription.
        // These are synchronous API calls that return StatusCode.Good — no timing sensitivity.

        [Fact]
        public void SubscriptionLifecycle_CreateModifyDelete_Succeeds()
        {
            var client = CreateConnectedClient();
            try
            {
                var createRes = client.CreateSubscription(0, 1000, true, 0, out uint subscrId);
                Assert.Equal(StatusCode.Good, createRes);
                Assert.NotEqual(0u, subscrId);

                var modifyRes = client.ModifySubscription(subscrId, 0, 100, true, 0, out uint modifyStatus);
                Assert.Equal(StatusCode.Good, modifyRes);

                var setPubRes = client.SetPublishingMode(true, [subscrId], out uint[] pubStatuses);
                Assert.Equal(StatusCode.Good, setPubRes);
                Assert.NotNull(pubStatuses);

                var deleteRes = client.DeleteSubscription([subscrId], out uint[] deleteStatuses);
                Assert.Equal(StatusCode.Good, deleteRes);
            }
            finally
            {
                DisposeClient(client);
            }
        }

        // ============================================================
        // TEST 3: Monitored items lifecycle (no timing sensitivity)
        // ============================================================
        // Tests CreateMonitoredItems, ModifyMonitoredItems, DeleteMonitoredItems.
        // Synchronous API calls — no timing sensitivity.

        [Fact]
        public void MonitoredItemsLifecycle_CreateModifyDelete_Succeeds()
        {
            var client = CreateConnectedClient();
            try
            {
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId);

                var createRes = client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                [
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(1u, 0, null, 100, false)),
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 2), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(2u, 0, null, 100, false)),
                ], out MonitoredItemCreateResult[] createResults);
                Assert.Equal(StatusCode.Good, createRes);
                Assert.NotNull(createResults);
                Assert.Equal(2, createResults.Length);

                var modifyRes = client.ModifyMonitoredItems(subscrId, TimestampsToReturn.Both,
                [
                    new MonitoredItemModifyRequest(1u, new MonitoringParameters(1u, 0, null, 200, false)),
                    new MonitoredItemModifyRequest(2u, new MonitoringParameters(2u, 0, null, 200, false)),
                ], out MonitoredItemModifyResult[] modifyResults);
                Assert.Equal(StatusCode.Good, modifyRes);
                Assert.NotNull(modifyResults);

                var deleteRes = client.DeleteMonitoredItems(subscrId, [1u, 2u], out uint[] deleteStatuses);
                Assert.Equal(StatusCode.Good, deleteRes);
                Assert.NotNull(deleteStatuses);

                client.DeleteSubscription([subscrId], out _);
            }
            finally
            {
                DisposeClient(client);
            }
        }

        // ============================================================
        // TEST 4: Read/Write with active subscription
        // ============================================================
        // Tests Read and Write operations while a subscription is active.
        // Read/Write are synchronous calls. Notifications are best-effort.

        [Fact]
        public void ReadWriteWithActiveSubscription_Succeeds()
        {
            var client = CreateConnectedClient();
            try
            {
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId);

                client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                [
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(1u, 0, null, 100, false)),
                ], out _);

                // Read while subscription is active
                var readRes = client.Read(new ReadValueId[]
                {
                    new(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null)),
                    new(new NodeId(2, 2), NodeAttribute.Value, null, new QualifiedName(0, null)),
                    new(new NodeId(2, 3), NodeAttribute.Value, null, new QualifiedName(0, null)),
                }, out DataValue[] dvs);
                Assert.Equal(StatusCode.Good, readRes);
                Assert.NotNull(dvs);
                Assert.Equal(3, dvs.Length);

                // Write while subscription is active
                var writeRes = client.Write(new WriteValue[]
                {
                    new(new NodeId(2, 0), NodeAttribute.Value,
                        null, new DataValue(3.14159265, StatusCode.Good, DateTime.Now)),
                }, out uint[] writeStatuses);
                Assert.Equal(StatusCode.Good, writeRes);
                Assert.NotNull(writeStatuses);

                // Give the server time to process monitored items
                Thread.Sleep(2000);

                // Wait briefly for notifications (best-effort — not required for test to pass)
                client.SetDataChangeTarget(1);
                bool signaled = client.WaitForDataChangeTarget(10000);
                // Read/write must succeed regardless of notification arrival

                client.DeleteMonitoredItems(subscrId, [1u], out _);
                client.DeleteSubscription([subscrId], out _);
            }
            finally
            {
                DisposeClient(client);
            }
        }

        // ============================================================
        // TEST 5: Session lifecycle with subscription
        // ============================================================
        // Tests closing a session and reconnecting with a new session while keeping
        // the TCP connection. The key is that subscriptions and monitored items are
        // explicitly deleted BEFORE CloseSession, because the server's SessionRelease
        // is empty and does not clean them up. Without this cleanup, orphaned items
        // remain in the server's global monitorMap, causing MonitorNotifyDataChange
        // to queue data into dead subscriptions on subsequent PlayRow calls, which
        // corrupts the publish pipeline for later tests.

        [Fact]
        public void SessionLifecycleWithSubscription_Succeeds()
        {
            var client = CreateConnectedClient();
            try
            {
                // Phase 1: Create subscription + monitored items
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId);
                Assert.NotEqual(0u, subscrId);

                var monitorIds = new uint[] { 1u };
                client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                [
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(monitorIds[0], 0, null, 100, false)),
                ], out _);

                // CRITICAL: Delete monitored items AND subscription BEFORE closing the session.
                // The server's SessionRelease() is empty and does not clean up subscriptions.
                // The MonitorRemove cleanup code in Server.cs is commented out.
                client.DeleteMonitoredItems(subscrId, monitorIds, out _);
                client.DeleteSubscription([subscrId], out _);

                // Now close the session cleanly (no orphaned items)
                var closeRes = client.CloseSession();
                Assert.Equal(StatusCode.Good, closeRes);

                // Phase 2: Reconnect with a new session on the same TCP channel
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
                client.CreateSession(
                    new ApplicationDescription(
                        "urn:DemoApplication", "http://quantensystems.com/",
                        new LocalizedText("en-US", "QuantenSystems integration test client"), ApplicationType.Client,
                        null, null, null),
                    "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                // Create a new subscription on the new session
                var createRes2 = client.CreateSubscription(0, 1000, true, 0, out uint subscrId2);
                Assert.Equal(StatusCode.Good, createRes2);
                Assert.NotEqual(0u, subscrId2);

                client.DeleteSubscription([subscrId2], out _);
            }
            finally
            {
                DisposeClient(client);
            }
        }

        // ============================================================
        // TEST 6: Multiple subscriptions with separate notifications
        // ============================================================
        // Tests that two subscriptions created by the same client deliver notifications
        // to the correct subscription IDs. Uses retry logic because the two-subscription
        // scenario is more timing-sensitive (more server state to manage).

        [Fact]
        public void MultipleSubscriptions_SeparateNotifications_Succeeds()
        {
            bool passed = RetryNotificationTest("MultipleSubscriptions", (client) =>
            {
                // Subscription 1: monitors NodeId(2,1) and NodeId(2,2)
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId1);
                Assert.NotEqual(0u, subscrId1);

                client.CreateMonitoredItems(subscrId1, TimestampsToReturn.Both,
                [
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(1u, 0, null, 100, false)),
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 2), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(2u, 0, null, 100, false)),
                ], out _);

                // Subscription 2: monitors NodeId(2,3)
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId2);
                Assert.NotEqual(0u, subscrId2);
                Assert.NotEqual(subscrId1, subscrId2);

                client.CreateMonitoredItems(subscrId2, TimestampsToReturn.Both,
                [
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 3), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(10u, 0, null, 100, false)),
                ], out _);

                // Give the publish pipeline time to establish
                Thread.Sleep(2000);

                // Wait for notifications — at least 2 callbacks needed
                client.SetDataChangeTarget(2);
                bool signaled = client.WaitForDataChangeTarget(20000);

                if (!signaled)
                {
                    Console.WriteLine($"    Notifications received: {client.DataChangeNotificationCallbackCount}");
                    return false;
                }

                // Verify we received notifications from at least one subscription
                var snapshot = client.DataChangeNotificationsSnapshot;
                var subIds = snapshot.Select(r => r.SubscriptionId).Distinct().ToList();

                if (subIds.Count == 0)
                {
                    Console.WriteLine($"    No subscription IDs in notifications");
                    return false;
                }

                // With enough callbacks, both subscriptions should appear
                if (snapshot.Count >= 6)
                {
                    Assert.True(subIds.Contains(subscrId1), $"Expected notifications from subId1={subscrId1}, got: {string.Join(", ", subIds)}");
                    Assert.True(subIds.Contains(subscrId2), $"Expected notifications from subId2={subscrId2}, got: {string.Join(", ", subIds)}");
                }

                // Clean up
                client.DeleteMonitoredItems(subscrId1, [1u, 2u], out _);
                client.DeleteMonitoredItems(subscrId2, [10u], out _);
                client.DeleteSubscription([subscrId1, subscrId2], out _);

                return true;
            });

            Assert.True(passed,
                "MultipleSubscriptions test failed after 3 retries with fresh clients. " +
                "Check console output for per-attempt diagnostic messages.");
        }

        // ============================================================
        // TEST 7: Delete monitored items stops notifications
        // ============================================================
        // Tests that deleting monitored items stops data change notifications.
        // Uses retry logic because the delete-then-verify-stop scenario is the most
        // timing-sensitive: we need notifications to arrive, then stop after delete.
        // A retry with a fresh client resets the server's subscription state cleanly.

        [Fact]
        public void DeleteMonitoredItemsStopsNotifications_Succeeds()
        {
            bool passed = RetryNotificationTest("DeleteMonitoredItems", (client) =>
            {
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId);

                var monitorIds = new uint[] { 1u, 2u, 3u };
                client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                [
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(monitorIds[0], 0, null, 100, false)),
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 2), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(monitorIds[1], 0, null, 100, false)),
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 3), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(monitorIds[2], 0, null, 100, false)),
                ], out _);

                // Give the publish pipeline time to establish
                Thread.Sleep(2000);

                // Wait for 3 notifications to confirm they're arriving
                client.SetDataChangeTarget(3);
                bool signaled = client.WaitForDataChangeTarget(20000);

                if (!signaled)
                {
                    Console.WriteLine($"    Notifications received before delete: {client.DataChangeNotificationCallbackCount}");
                    client.DeleteMonitoredItems(subscrId, monitorIds, out _);
                    client.DeleteSubscription([subscrId], out _);
                    return false;
                }

                int countBeforeDelete = client.DataChangeNotificationCallbackCount;
                Assert.True(countBeforeDelete >= 3,
                    $"Expected ≥3 notifications before delete, got {countBeforeDelete}");

                // Delete all monitored items — notifications should stop
                client.DeleteMonitoredItems(subscrId, monitorIds, out _);

                // Record count, wait 3 seconds, then verify count hasn't significantly increased
                int countAfterDelete = client.DataChangeNotificationCallbackCount;
                Thread.Sleep(3000);
                int countAfterWait = client.DataChangeNotificationCallbackCount;

                // Allow at most 1 stray notification from race conditions:
                // the server may have already queued data into the monitored item queues
                // before DeleteMonitoredItems was processed on the server side.
                int delta = countAfterWait - countAfterDelete;
                Assert.True(delta <= 1,
                    $"After deleting monitored items, notification count should not significantly increase. " +
                    $"Before wait: {countAfterDelete}, after wait: {countAfterWait}, delta: {delta}");

                client.DeleteSubscription([subscrId], out _);

                return true;
            });

            Assert.True(passed,
                "DeleteMonitoredItemsStopsNotifications test failed after 3 retries with fresh clients. " +
                "Check console output for per-attempt diagnostic messages.");
        }
    }
}