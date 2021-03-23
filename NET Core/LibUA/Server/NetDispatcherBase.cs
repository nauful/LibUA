
// Type: LibUA.Server.NetDispatcherBase



using LibUA.Core;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace LibUA.Server
{
    public class NetDispatcherBase
    {
        private uint uaStatusCode = 0;
        protected Application app = null;
        protected ILogger logger = null;
        private readonly Master server = null;
        protected Socket socket = null;
        private readonly object csDispatching = new object();
        protected Thread thread = null;
        protected bool threadAbort = false;
        protected SLChannel config = null;
        protected uint nextSubscriptionID = 1;
        protected Queue<RequestHeader> pendingNotificationRequests = null;
        protected Dictionary<uint, Queue<uint>> pendingSubscriptionAcknowledgements = null;
        protected Dictionary<uint, Subscription> subscriptionMap = null;
        protected Stack<int> availableContinuationPoints = null;
        protected Dictionary<int, ContinuationPointBrowse> continuationBrowse = null;
        protected Dictionary<int, ContinuationPointHistory> continuationHistory = null;
        public const int MaxContinuationPoints = 256;
        public const int MaxPublishRequests = 1024;
        public const int MaxMonitoredPerSubscription = 65536;
        public const int MaxTokenLifetime = 600000;
        public const uint MaxBrowseResults = 10000;
        public const uint MaxHistoryReadNodes = 256;
        public const uint MaxSubscriptionAcknowledgementsPerPublish = 16;
        public const int MessageEncodedBlockStart = 16;
        public const int ChunkHeaderOverhead = 24;
        public const double UsableMessageSizeFactor = 0.8;
        public const int TLPaddingOverhead = 1024;
        protected const int ErrorInternal = -1;
        protected const int ErrorParseFail = -2;
        protected const int ErrorRespWrite = -3;
        protected const int ErrorClosed = -4;
        public const int PulseInterval = 100;
        protected int maximumMessageSize;

        public uint UAStatusCode
        {
            get
            {
                return this.uaStatusCode;
            }
            protected set
            {
                this.uaStatusCode = value;
            }
        }

        public NetDispatcherBase(Master server, Application app, Socket socket, ILogger logger)
        {
            this.app = app;
            this.logger = logger;
            this.server = server;
            this.socket = socket;
            this.maximumMessageSize = server.MaximumMessageSize;
            this.UAStatusCode = 0U;
            this.availableContinuationPoints = new Stack<int>();
            for (int maxValue = byte.MaxValue; maxValue >= 0; --maxValue)
            {
                this.availableContinuationPoints.Push(1 + maxValue);
            }

            this.continuationBrowse = new Dictionary<int, ContinuationPointBrowse>();
            this.continuationHistory = new Dictionary<int, ContinuationPointHistory>();
            this.pendingNotificationRequests = new Queue<RequestHeader>();
            this.pendingSubscriptionAcknowledgements = new Dictionary<uint, Queue<uint>>();
            this.subscriptionMap = new Dictionary<uint, Subscription>();
            this.thread = new Thread(new ParameterizedThreadStart(NetDispatcherBase.ThreadTarget));
        }

        protected static void ThreadTarget(object args)
        {
            (args as NetDispatcherBase).ThreadTarget();
        }

        protected void MarkPositionAsSize(MemoryBuffer mb)
        {
            uint position = (uint)mb.Position;
            mb.Position = 4;
            mb.Encode(position);
            mb.Position = (int)position;
        }

        protected void MarkPositionAsSize(MemoryBuffer mb, uint position)
        {
            int position1 = mb.Position;
            mb.Position = 4;
            mb.Encode(position);
            mb.Position = position1;
        }

        private void TLError(uint statusCode)
        {
            MemoryBuffer memoryBuffer = new MemoryBuffer(1024);
            if (true & memoryBuffer.Encode(1179800133U) & memoryBuffer.Encode(0U) & memoryBuffer.Encode(statusCode) & memoryBuffer.EncodeUAString(string.Format("TL error 0x{0}", statusCode.ToString("X"))))
            {
                this.MarkPositionAsSize(memoryBuffer);
                this.socket.Send(memoryBuffer.Buffer, memoryBuffer.Position, SocketFlags.None);
            }
            if (this.logger == null)
            {
                return;
            }

            this.logger.Log(LogLevel.Error, string.Format("Sent TL error 0x{0}", statusCode.ToString("X")));
        }

        private void ThreadTarget()
        {
            Application.SessionCreationInfo sessionInfo = new Application.SessionCreationInfo()
            {
                Endpoint = this.socket.RemoteEndPoint
            };
            if (this.logger != null)
            {
                this.logger.Log(LogLevel.Info, string.Format("Accepted connection from {0}", sessionInfo.Endpoint));
            }

            this.config = new SLChannel();
            this.config.Endpoint = this.socket.RemoteEndPoint as IPEndPoint;
            this.config.Session = this.app.SessionCreate(sessionInfo);
            this.config.SLState = ConnectionState.Opening;
            int num1 = 0;
            byte[] numArray1 = new byte[this.maximumMessageSize];
            DateTime minValue = DateTime.MinValue;
            while (this.socket.Connected && !this.threadAbort)
            {
                while (this.NeedsPulse())
                {
                    Monitor.Enter(this.csDispatching);
                    try
                    {
                        if (!this.Pulse())
                        {
                            if (this.logger != null)
                            {
                                this.logger.Log(LogLevel.Error, "Pulse failed");
                            }

                            num1 = -1;
                            break;
                        }
                    }
                    finally
                    {
                        Monitor.Exit(this.csDispatching);
                    }
                }
                if (this.socket.Poll(100000, SelectMode.SelectRead))
                {
                    int size = this.maximumMessageSize - num1;
                    if (size >= 0)
                    {
                        int num2;
                        try
                        {
                            num2 = this.socket.Receive(numArray1, num1, size, SocketFlags.None);
                        }
                        catch
                        {
                            break;
                        }
                        if (num2 != 0)
                        {
                            num1 += num2;
                            if (num1 > this.maximumMessageSize)
                            {
                                if (this.logger != null)
                                {
                                    this.logger.Log(LogLevel.Error, string.Format("Received {0} but maximum message size is {1}", num1, maximumMessageSize));
                                    break;
                                }
                                break;
                            }
                            while (num1 > 0 && this.UAStatusCode == 0U)
                            {
                                Monitor.Enter(this.csDispatching);
                                int sourceIndex = -1;
                                try
                                {
                                    sourceIndex = this.Consume(new MemoryBuffer(numArray1, num1));
                                }
                                catch (NotImplementedException)
                                {
                                    if (this.UAStatusCode == 0U)
                                    {
                                        this.UAStatusCode = 2151677952U;
                                    }

                                    sourceIndex = -1;
                                }
                                catch
                                {
                                    sourceIndex = -1;
                                }
                                finally
                                {
                                    Monitor.Exit(this.csDispatching);
                                }
                                if (sourceIndex < 0)
                                {
                                    if (this.UAStatusCode == 0U)
                                    {
                                        if (sourceIndex == -1)
                                        {
                                            this.UAStatusCode = 2147614720U;
                                        }

                                        if (sourceIndex == -2)
                                        {
                                            this.UAStatusCode = 2147942400U;
                                        }

                                        if (sourceIndex == -3)
                                        {
                                            this.UAStatusCode = 2148007936U;
                                        }
                                    }
                                    num1 = -1;
                                    break;
                                }
                                if (sourceIndex != 0)
                                {
                                    if (sourceIndex >= num1)
                                    {
                                        if (sourceIndex > num1 && this.logger != null)
                                        {
                                            this.logger.Log(LogLevel.Error, string.Format("Consumed {0} but accumulated message size is {1}", sourceIndex, num1));
                                        }

                                        num1 = 0;
                                    }
                                    else
                                    {
                                        int length = num1 - sourceIndex;
                                        byte[] numArray2 = new byte[this.maximumMessageSize];
                                        Array.Copy(numArray1, sourceIndex, numArray2, 0, length);
                                        numArray1 = numArray2;
                                        num1 = length;
                                    }
                                    if (this.UAStatusCode > 0U)
                                    {
                                        this.threadAbort = true;
                                    }
                                }
                                else
                                {
                                    break;
                                }
                            }
                            if (num1 >= this.maximumMessageSize)
                            {
                                if (this.logger != null)
                                {
                                    this.logger.Log(LogLevel.Error, string.Format("Received {0} but maximum message size is {1}", num1, maximumMessageSize));
                                    break;
                                }
                                break;
                            }
                            if (num1 < 0)
                            {
                                break;
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
            }
            if (this.UAStatusCode > 0U)
            {
                this.TLError(this.UAStatusCode);
            }

            if (this.config.Session != null)
            {
                this.app.SessionRelease(this.config.Session);
            }

            this.socket.Shutdown(SocketShutdown.Send);
            this.socket.Close();
            this.server.RemoveDispatcher(this);
            if (this.logger == null)
            {
                return;
            }

            this.logger.Log(LogLevel.Info, string.Format("Ended connection from {0}", sessionInfo.Endpoint));
        }

        protected virtual bool NeedsPulse()
        {
            return false;
        }

        protected virtual bool Pulse()
        {
            return false;
        }

        protected virtual int Consume(MemoryBuffer recvBuf)
        {
            return -1;
        }

        public void Close()
        {
            if (this.thread != null)
            {
                this.threadAbort = true;
                this.thread.Join();
                this.thread = null;
            }
            this.server.RemoveDispatcher(this);
        }
    }
}
