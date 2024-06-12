﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using LibUA.Core;
using Microsoft.Extensions.Logging;

namespace LibUA
{
    namespace Server
    {
        public class NetDispatcherBase
        {
            public const int MaxContinuationPoints = 256;
            public const int MaxPublishRequests = 1024;
            public const int MaxMonitoredPerSubscription = 65536;
            public const int MaxTokenLifetime = 600 * 1000;
            public const uint MaxBrowseResults = 10000;
            public const uint MaxHistoryReadNodes = 256;
            public const uint MaxSubscriptionAcknowledgementsPerPublish = 16;

            // Message type, message size, secure channel ID, security token ID
            public const int MessageEncodedBlockStart = 16;
            public const int ChunkHeaderOverhead = 4 * 6;

            public const double UsableMessageSizeFactor = 0.8;
            public const int TLPaddingOverhead = 1024;
            private uint uaStatusCode = 0;
            public uint UAStatusCode
            {
                get { return uaStatusCode; }
                protected set { uaStatusCode = value; }
            }

            protected const int ErrorInternal = -1;
            protected const int ErrorParseFail = -2;
            protected const int ErrorRespWrite = -3;
            protected const int ErrorClosed = -4;

            public const int PulseInterval = 100;

            protected Application app = null;
            protected ILogger logger = null;
            private readonly Master server = null;
            protected Stream stream = null;
            protected int maximumMessageSize;

            // Ensure publishes are in sequence and not in parallel
            private readonly object csDispatching = new object();

            protected Thread thread = null;
            protected bool threadAbort = false;

            protected SLChannel config = null;

            protected UInt32 nextSubscriptionID = 1;
            protected Queue<RequestHeader> pendingNotificationRequests = null;
            protected Dictionary<uint, Queue<uint>> pendingSubscriptionAcknowledgements = null;
            //protected Dictionary<uint, Application.MonitorDispatcherConfiguration> monitorMap = null;
            //protected List<Application.MonitorDispatcherConfiguration> monitorList = null;

            protected Dictionary<UInt32, Subscription> subscriptionMap = null;

            protected Stack<int> availableContinuationPoints = null;
            protected Dictionary<int, ContinuationPointBrowse> continuationBrowse = null;
            protected Dictionary<int, ContinuationPointHistory> continuationHistory = null;

            public NetDispatcherBase(Master server, Application app, Stream stream, ILogger logger)
            {
                this.app = app;
                this.logger = logger;
                this.server = server;
                this.stream = stream;
                this.maximumMessageSize = server.MaximumMessageSize;

                this.UAStatusCode = (uint)StatusCode.Good;

                availableContinuationPoints = new Stack<int>();
                for (int i = MaxContinuationPoints - 1; i >= 0; i--)
                {
                    availableContinuationPoints.Push(1 + i);
                }
                continuationBrowse = new Dictionary<int, ContinuationPointBrowse>();
                continuationHistory = new Dictionary<int, ContinuationPointHistory>();

                pendingNotificationRequests = new Queue<RequestHeader>();
                pendingSubscriptionAcknowledgements = new Dictionary<uint, Queue<uint>>();
                //monitorMap = new Dictionary<uint, Application.MonitorDispatcherConfiguration>();
                //monitorList = new List<Application.MonitorDispatcherConfiguration>();

                subscriptionMap = new Dictionary<uint, Subscription>();

                thread = new Thread(new ParameterizedThreadStart(ThreadTarget));
                thread.Name = $"Client Thread {(stream as NetworkStream).Socket.RemoteEndPoint}";
            }

            protected static void ThreadTarget(object args)
            {
                (args as NetDispatcherBase).ThreadTarget();
            }

            // Skip MessageType and ChunkType, write MessageSize
            protected void MarkPositionAsSize(MemoryBuffer mb)
            {
                UInt32 pos = (UInt32)mb.Position;
                mb.Position = 4;
                mb.Encode(pos);
                mb.Position = (int)pos;
            }

            protected void MarkPositionAsSize(MemoryBuffer mb, UInt32 position)
            {
                int restorePos = mb.Position;
                mb.Position = 4;
                mb.Encode(position);
                mb.Position = restorePos;
            }

            private void TLError(uint statusCode)
            {
                using var respBuf = new MemoryBuffer(1 << 10);
                bool succeeded = true;
                succeeded &= respBuf.Encode((uint)(MessageType.Error) | ((uint)'F' << 24));
                succeeded &= respBuf.Encode((UInt32)0);
                succeeded &= respBuf.Encode((UInt32)statusCode);
                succeeded &= respBuf.EncodeUAString(string.Format("TL error 0x{0}", statusCode.ToString("X")));

                if (succeeded)
                {
                    MarkPositionAsSize(respBuf);

                    try
                    {
                        stream.Write(respBuf.Buffer, 0, respBuf.Position);
                    }
                    catch (SocketException ex)
                    {
                        logger?.Log(LogLevel.Error, string.Format("Socket error {1} for TL error 0x{0}", statusCode.ToString("X"), ex.Message));
                    }
                }

                logger?.Log(LogLevel.Error, string.Format("Sent TL error 0x{0}", statusCode.ToString("X")));
            }

            private void ThreadTarget()
            {
                var sessionInfo = new Application.SessionCreationInfo()
                {
                    Endpoint = (stream as NetworkStream)?.Socket?.RemoteEndPoint
                };

                logger?.Log(LogLevel.Information, string.Format("Accepted connection from {0}", sessionInfo.Endpoint));

                config = new SLChannel
                {
                    Endpoint = sessionInfo.Endpoint as IPEndPoint,
                    Session = app.SessionCreate(sessionInfo),
                    SLState = ConnectionState.Opening
                };

                int recvAccumSize = 0;
                var recvBuffer = new byte[maximumMessageSize];
                while (stream != null)
                {
                    if (threadAbort)
                    {
                        break;
                    }

                    while (NeedsPulse())
                    {
                        Monitor.Enter(csDispatching);

                        try
                        {
                            //var sw = new System.Diagnostics.Stopwatch();
                            //sw.Start();
                            if (!Pulse())
                            {
                                logger?.Log(LogLevel.Error, "Pulse failed");
                                recvAccumSize = -1;
                                break;
                            }
                            //sw.Stop();
                            //Console.WriteLine("Pulse in {0}", sw.Elapsed.ToString());
                        }
                        finally
                        {
                            Monitor.Exit(csDispatching);
                        }
                    }

                    try
                    {
                        if (!(stream as NetworkStream).DataAvailable)
                        {
                            continue;
                        }
                    }
                    catch (SocketException)
                    {
                        // Disconnected
                        break;
                    }

                    int bytesAvailable = maximumMessageSize - recvAccumSize;
                    if (bytesAvailable < 0)
                    {
                        break;
                    }


                    int bytesRead;
                    try
                    {
                        bytesRead = stream.Read(recvBuffer, recvAccumSize, bytesAvailable);
                    }
                    catch
                    {
                        break;
                    }

                    if (bytesRead == 0)
                    {
                        // Disconnected
                        break;
                    }

                    recvAccumSize += bytesRead;
                    if (recvAccumSize > maximumMessageSize)
                    {
                        logger?.Log(LogLevel.Error, string.Format("Received {0} but maximum message size is {1}", recvAccumSize, maximumMessageSize));
                        break;
                    }

                    while (recvAccumSize > 0 && UAStatusCode == (uint)StatusCode.Good)
                    {
                        Monitor.Enter(csDispatching);
                        int consumedSize = -1;

                        try
                        {
                            consumedSize = Consume(new MemoryBuffer(recvBuffer, recvAccumSize));
                        }
                        catch (NotImplementedException)
                        {
                            if (UAStatusCode == (uint)StatusCode.Good) { UAStatusCode = (uint)StatusCode.BadNotImplemented; }
                            consumedSize = ErrorInternal;
                        }
                        catch
                        {
                            consumedSize = ErrorInternal;
                        }
                        finally
                        {
                            Monitor.Exit(csDispatching);
                        }

                        if (consumedSize < 0)
                        {
                            if (UAStatusCode == (uint)StatusCode.Good)
                            {
                                if (consumedSize == ErrorInternal) { UAStatusCode = (uint)StatusCode.BadInternalError; }
                                if (consumedSize == ErrorParseFail) { UAStatusCode = (uint)StatusCode.BadDecodingError; }
                                if (consumedSize == ErrorRespWrite) { UAStatusCode = (uint)StatusCode.BadEncodingLimitsExceeded; }
                            }

                            // Handler failed
                            recvAccumSize = -1;
                            break;
                        }
                        else if (consumedSize == 0)
                        {
                            // Not enough to read a message
                            break;
                        }
                        else if (consumedSize >= recvAccumSize)
                        {
                            if (consumedSize > recvAccumSize)
                            {
                                logger?.Log(LogLevel.Error, string.Format("Consumed {0} but accumulated message size is {1}", consumedSize, recvAccumSize));
                            }

                            recvAccumSize = 0;
                        }
                        else
                        {
                            int newSize = recvAccumSize - consumedSize;

                            var newRecvBuffer = new byte[maximumMessageSize];
                            Array.Copy(recvBuffer, consumedSize, newRecvBuffer, 0, newSize);
                            recvBuffer = newRecvBuffer;

                            recvAccumSize = newSize;
                        }

                        if (UAStatusCode != (uint)StatusCode.Good)
                        {
                            threadAbort = true;
                        }
                    }

                    // Cannot receive more or process existing
                    if (recvAccumSize >= maximumMessageSize)
                    {
                        logger?.Log(LogLevel.Error, string.Format("Received {0} but maximum message size is {1}", recvAccumSize, maximumMessageSize));
                        break;
                    }

                    if (recvAccumSize < 0)
                    {
                        break;
                    }
                }

                if (UAStatusCode != (uint)StatusCode.Good)
                {
                    TLError(UAStatusCode);
                }

                if (config.Session != null)
                {
                    app.SessionRelease(config.Session);
                }

                try
                {
                    (stream as NetworkStream)?.Socket?.Shutdown(SocketShutdown.Send);
                    stream.Close();
                }
                catch (SocketException)
                {
                    // Disconnected
                }

                server.RemoveDispatcher(this);

                //foreach (var cfg in monitorMap.Values)
                //{
                //	app.MonitorDispatcherRemove(cfg);
                //}

                logger?.Log(LogLevel.Information, string.Format("Ended connection from {0}", sessionInfo.Endpoint));
            }

            virtual protected bool NeedsPulse()
            {
                return false;
            }

            virtual protected bool Pulse()
            {
                return false;
            }

            virtual protected int Consume(MemoryBuffer recvBuf)
            {
                return -1;
            }

            public void Close()
            {
                if (thread != null)
                {
                    threadAbort = true;

                    thread.Join();
                    thread = null;
                }

                server.RemoveDispatcher(this);
            }
        }
    }
}
