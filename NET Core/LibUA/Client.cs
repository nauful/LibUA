
using LibUA.Core;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace LibUA
{
    public class Client : IDisposable
    {
        protected SLChannel config = null;
        private Semaphore cs = null;
        private Semaphore csDispatching = null;
        private Semaphore csWaitForSecure = null;
        private uint nextRequestHandle = 0;
        protected TcpClient tcp = null;
        protected Thread thread = null;
        private bool threadAbort = false;
        private long totalBytesSent = 0;
        private long totalBytesRecv = 0;
        private System.Timers.Timer renewTimer = null;
        private HashSet<Tuple<uint, uint>> recvPendingRequests = null;
        private Dictionary<Tuple<uint, uint>, Client.RecvHandler> recvQueue = null;
        private Dictionary<Tuple<uint, uint>, ManualResetEvent> recvNotify = null;
        private bool nextPublish = false;
        private HashSet<uint> publishReqs = null;
        private const int MessageEncodedBlockStart = 16;
        private const int ChunkHeaderOverhead = 24;
        private const double UsableMessageSizeFactor = 0.8;
        private const int TLPaddingOverhead = 1024;
        public const int ListenerInterval = 100;
        public readonly string Target;
        public readonly int Port;
        public readonly string Path;
        public readonly int Timeout;
        private int MaximumMessageSize;
        private StatusCode recvHandlerStatus;

        public event Client.ConnectionClosed OnConnectionClosed = null;

        public virtual X509Certificate2 ApplicationCertificate
        {
            get
            {
                return null;
            }
        }

        public virtual RSACryptoServiceProvider ApplicationPrivateKey
        {
            get
            {
                return null;
            }
        }

        public long TotalBytesSent
        {
            get
            {
                return this.totalBytesSent;
            }
        }

        public long TotalBytesRecv
        {
            get
            {
                return this.totalBytesRecv;
            }
        }

        public bool IsConnected
        {
            get
            {
                return this.tcp != null && this.tcp.Connected;
            }
        }

        public Client(string Target, int Port, int Timeout, int MaximumMessageSize = 262144)
          : this(Target, Port, null, Timeout, MaximumMessageSize)
        {
        }

        public Client(string Target, int Port, string Path, int Timeout, int MaximumMessageSize = 262144)
        {
            this.Target = Target;
            this.Port = Port;
            this.Path = Path;
            this.Timeout = Timeout;
            this.MaximumMessageSize = MaximumMessageSize;
        }

        public StatusCode OpenSecureChannel(
          MessageSecurityMode messageSecurityMode,
          SecurityPolicy securityPolicy,
          byte[] serverCert)
        {
            this.config.SecurityPolicy = securityPolicy;
            this.config.MessageSecurityMode = messageSecurityMode;
            this.config.RemoteCertificateString = serverCert;
            try
            {
                this.config.RemoteCertificate = new X509Certificate2(serverCert);
            }
            catch
            {
                return StatusCode.BadCertificateInvalid;
            }
            try
            {
                return this.OpenSecureChannelInternal(false);
            }
            finally
            {
                this.csWaitForSecure.Release();
            }
        }

        private StatusCode RenewSecureChannel()
        {
            try
            {
                return this.OpenSecureChannelInternal(true);
            }
            finally
            {
                this.csWaitForSecure.Release();
            }
        }

        private StatusCode OpenSecureChannelInternal(bool renew)
        {
            SecurityTokenRequestType tokenRequestType = renew ? SecurityTokenRequestType.Renew : SecurityTokenRequestType.Issue;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                if (tokenRequestType == SecurityTokenRequestType.Issue)
                {
                    this.config.ChannelID = 0U;
                }

                bool flag1 = true & memoryBuffer.Encode(1179537487U) & memoryBuffer.Encode(0U) & memoryBuffer.Encode(this.config.ChannelID) & memoryBuffer.EncodeUAString(Types.SLSecurityPolicyUris[(int)this.config.SecurityPolicy]);
                bool flag2;
                if (this.config.SecurityPolicy == SecurityPolicy.None)
                {
                    flag2 = flag1 & memoryBuffer.EncodeUAByteString(null) & memoryBuffer.EncodeUAByteString(null);
                }
                else
                {
                    byte[] str1 = this.ApplicationCertificate.Export(X509ContentType.Cert);
                    byte[] str2 = UASecurity.SHACalculate(this.config.RemoteCertificateString, SecurityPolicy.Basic128Rsa15);
                    flag2 = flag1 & memoryBuffer.EncodeUAByteString(str1) & memoryBuffer.EncodeUAByteString(str2);
                }
                int position = memoryBuffer.Position;
                if (tokenRequestType == SecurityTokenRequestType.Issue)
                {
                    this.config.LocalSequence = new SLSequence()
                    {
                        SequenceNumber = 51U,
                        RequestId = 1U
                    };
                }

                bool flag3 = flag2 & memoryBuffer.Encode(this.config.LocalSequence.SequenceNumber) & memoryBuffer.Encode(this.config.LocalSequence.RequestId) & memoryBuffer.Encode(new NodeId(RequestCode.OpenSecureChannelRequest));
                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                uint v1 = 0;
                uint v2 = (uint)tokenRequestType;
                uint messageSecurityMode = (uint)this.config.MessageSecurityMode;
                byte[] str3 = null;
                uint v3 = 300000;
                if (this.config.SecurityPolicy != SecurityPolicy.None)
                {
                    str3 = UASecurity.GenerateRandomBytes(UASecurity.SymmetricKeySizeForSecurityPolicy(this.config.SecurityPolicy, -1));
                }

                bool flag4 = flag3 & memoryBuffer.Encode(req) & memoryBuffer.Encode(v1) & memoryBuffer.Encode(v2) & memoryBuffer.Encode(messageSecurityMode) & memoryBuffer.EncodeUAByteString(str3) & memoryBuffer.Encode(v3);
                this.config.LocalNonce = str3;
                if (!flag4)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                if (this.config.SecurityPolicy != SecurityPolicy.None)
                {
                    ;
                }

                if (this.config.SecurityPolicy == SecurityPolicy.None)
                {
                    this.MarkPositionAsSize(memoryBuffer);
                }
                else
                {
                    UASecurity.PaddingAlgorithm paddingAlgorithm = UASecurity.PaddingMethodForSecurityPolicy(this.config.SecurityPolicy);
                    int signatureSize = UASecurity.CalculateSignatureSize(this.ApplicationCertificate);
                    int paddingSize = UASecurity.CalculatePaddingSize(this.config.RemoteCertificate, this.config.SecurityPolicy, memoryBuffer.Position - position, signatureSize);
                    if (paddingSize > 0)
                    {
                        byte num = (byte)(paddingSize - 1 & byte.MaxValue);
                        byte[] Add = new byte[paddingSize];
                        for (int index = 0; index < paddingSize; ++index)
                        {
                            Add[index] = num;
                        }

                        memoryBuffer.Append(Add);
                    }
                    int num1 = memoryBuffer.Position + signatureSize;
                    int num2 = position + UASecurity.CalculateEncryptedSize(this.config.RemoteCertificate, num1 - position, paddingAlgorithm);
                    this.MarkPositionAsSize(memoryBuffer, (uint)num2);
                    byte[] Add1 = UASecurity.RsaPkcs15Sha_Sign(new ArraySegment<byte>(memoryBuffer.Buffer, 0, memoryBuffer.Position), ApplicationPrivateKey, this.config.SecurityPolicy);
                    memoryBuffer.Append(Add1);
                    byte[] Add2 = UASecurity.RsaPkcs15Sha_Encrypt(new ArraySegment<byte>(memoryBuffer.Buffer, position, memoryBuffer.Position - position), this.config.RemoteCertificate, this.config.SecurityPolicy);
                    memoryBuffer.Position = position;
                    memoryBuffer.Append(Add2);
                    if (memoryBuffer.Position != num2)
                    {
                        return StatusCode.BadSecurityChecksFailed;
                    }
                }
                Tuple<uint, uint> key1 = new Tuple<uint, uint>(5132367U, 0U);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key1] = manualResetEvent;
                }

                this.tcp.Client.Send(memoryBuffer.Buffer, memoryBuffer.Position, SocketFlags.None);
                Interlocked.Add(ref this.totalBytesSent, memoryBuffer.Position);
                ++this.config.LocalSequence.SequenceNumber;
                uint num3 = this.config.LocalSequence.RequestId++;
                bool flag5 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key1);
                }

                if (!flag5)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    Tuple<uint, uint> key2 = new Tuple<uint, uint>(5132367U, 0U);
                    if (!this.recvQueue.TryGetValue(key2, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key2);
                }
                if (!recvHandler.RecvBuf.Decode(out uint _) || !recvHandler.RecvBuf.DecodeUAString(out string str4) || !recvHandler.RecvBuf.DecodeUAByteString(out byte[] str5))
                {
                    return StatusCode.BadDecodingError;
                }

                if (!recvHandler.RecvBuf.DecodeUAByteString(out byte[] str6))
                {
                    return StatusCode.BadDecodingError;
                }

                try
                {
                    if (str4 != Types.SLSecurityPolicyUris[(int)this.config.SecurityPolicy])
                    {
                        return StatusCode.BadSecurityPolicyRejected;
                    }
                }
                catch
                {
                    return StatusCode.BadSecurityPolicyRejected;
                }
                if (this.config.SecurityPolicy != SecurityPolicy.None)
                {
                    try
                    {
                        this.config.RemoteCertificate = new X509Certificate2(str5);
                        if (!UASecurity.VerifyCertificate(this.config.RemoteCertificate))
                        {
                            return StatusCode.BadCertificateInvalid;
                        }
                    }
                    catch
                    {
                        return StatusCode.BadCertificateInvalid;
                    }
                    if (!UASecurity.SHAVerify(this.ApplicationCertificate.Export(X509ContentType.Cert), str6, SecurityPolicy.Basic128Rsa15))
                    {
                        return StatusCode.BadSecurityChecksFailed;
                    }

                    UASecurity.PaddingMethodForSecurityPolicy(this.config.SecurityPolicy);
                    byte[] numArray = UASecurity.RsaPkcs15Sha_Decrypt(new ArraySegment<byte>(recvHandler.RecvBuf.Buffer, recvHandler.RecvBuf.Position, recvHandler.RecvBuf.Capacity - recvHandler.RecvBuf.Position), this.ApplicationCertificate, ApplicationPrivateKey, this.config.SecurityPolicy);
                    int length = Math.Min(numArray.Length, recvHandler.RecvBuf.Capacity - recvHandler.RecvBuf.Position);
                    Array.Copy(numArray, 0, recvHandler.RecvBuf.Buffer, recvHandler.RecvBuf.Position, length);
                }
                if (!recvHandler.RecvBuf.Decode(out uint v4) || !recvHandler.RecvBuf.Decode(out uint v5) || !recvHandler.RecvBuf.Decode(out NodeId id))
                {
                    return StatusCode.BadDecodingError;
                }

                if (!id.EqualsNumeric(0, 449U))
                {
                    return StatusCode.BadSecureChannelClosed;
                }

                if (!renew)
                {
                    this.config.RemoteSequence = new SLSequence()
                    {
                        RequestId = v5,
                        SequenceNumber = v4
                    };
                }

                if (!recvHandler.RecvBuf.Decode(out ResponseHeader resp) || !recvHandler.RecvBuf.Decode(out uint _) || (!recvHandler.RecvBuf.Decode(out uint v6) || !recvHandler.RecvBuf.Decode(out uint v7)) || (!recvHandler.RecvBuf.Decode(out ulong v8) || !recvHandler.RecvBuf.Decode(out uint v9) || !recvHandler.RecvBuf.DecodeUAByteString(out byte[] str7)))
                {
                    return StatusCode.BadDecodingError;
                }

                if (renew)
                {
                    this.config.PrevChannelID = new uint?(this.config.ChannelID);
                    this.config.PrevTokenID = new uint?(this.config.TokenID);
                }
                this.config.ChannelID = v6;
                this.config.TokenID = v7;
                this.config.TokenCreatedAt = DateTimeOffset.FromFileTime((long)v8);
                this.config.TokenLifetime = v9;
                this.config.RemoteNonce = str7;
                if (this.config.SecurityPolicy == SecurityPolicy.None)
                {
                    this.config.LocalKeysets = new SLChannel.Keyset[2]
                    {
            new SLChannel.Keyset(),
            new SLChannel.Keyset()
                    };
                    this.config.RemoteKeysets = new SLChannel.Keyset[2]
                    {
            new SLChannel.Keyset(),
            new SLChannel.Keyset()
                    };
                }
                else
                {
                    int count1 = UASecurity.SymmetricKeySizeForSecurityPolicy(this.config.SecurityPolicy, -1);
                    int num1 = UASecurity.SymmetricSignatureKeySizeForSecurityPolicy(this.config.SecurityPolicy);
                    int count2 = UASecurity.SymmetricBlockSizeForSecurityPolicy(this.config.SecurityPolicy);
                    byte[] array1 = UASecurity.PSHA(this.config.RemoteNonce, this.config.LocalNonce, num1 + count1 + count2, this.config.SecurityPolicy);
                    SLChannel.Keyset keyset1 = new SLChannel.Keyset(new ArraySegment<byte>(array1, 0, num1).ToArray(), new ArraySegment<byte>(array1, num1, count1).ToArray(), new ArraySegment<byte>(array1, num1 + count1, count2).ToArray());
                    byte[] array2 = UASecurity.PSHA(this.config.LocalNonce, this.config.RemoteNonce, num1 + count1 + count2, this.config.SecurityPolicy);
                    SLChannel.Keyset keyset2 = new SLChannel.Keyset(new ArraySegment<byte>(array2, 0, num1).ToArray(), new ArraySegment<byte>(array2, num1, count1).ToArray(), new ArraySegment<byte>(array2, num1 + count1, count2).ToArray());
                    if (this.config.LocalKeysets == null)
                    {
                        this.config.LocalKeysets = new SLChannel.Keyset[2]
                        {
              keyset1,
              new SLChannel.Keyset()
                        };
                        this.config.RemoteKeysets = new SLChannel.Keyset[2]
                        {
              keyset2,
              new SLChannel.Keyset()
                        };
                    }
                    else
                    {
                        this.config.LocalKeysets = new SLChannel.Keyset[2]
                        {
              keyset1,
              this.config.LocalKeysets[0]
                        };
                        this.config.RemoteKeysets = new SLChannel.Keyset[2]
                        {
              keyset2,
              this.config.RemoteKeysets[0]
                        };
                    }
                }
                return StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                if (!renew)
                {
                    this.CheckPostCall();
                }
            }
        }

        public StatusCode CloseSecureChannel()
        {
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Close);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = new NodeId(0U)
                };
                if (!(true & memoryBuffer.Encode(new NodeId(RequestCode.CloseSecureChannelRequest)) & memoryBuffer.Encode(req)))
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> index = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[index] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                return statusCode2 > StatusCode.Good ? statusCode2 : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        private StatusCode EncodeMessageHeader(
          MemoryBuffer sendBuf,
          bool needsEstablishedSL = true,
          MessageType messageType = MessageType.Message)
        {
            if (this.config.SLState != ConnectionState.Established & needsEstablishedSL)
            {
                return StatusCode.BadSecureChannelClosed;
            }

            if (!(true & sendBuf.Encode((uint)(messageType | (MessageType)1174405120)) & sendBuf.Encode(0U) & sendBuf.Encode(this.config.ChannelID) & sendBuf.Encode(this.config.TokenID) & sendBuf.Encode(this.config.LocalSequence.SequenceNumber) & sendBuf.Encode(this.config.LocalSequence.RequestId)))
            {
                return StatusCode.BadEncodingLimitsExceeded;
            }

            ++this.config.LocalSequence.SequenceNumber;
            ++this.config.LocalSequence.RequestId;
            return StatusCode.Good;
        }

        public StatusCode GetEndpoints(
          out EndpointDescription[] endpointDescs,
          string[] localeIDs)
        {
            endpointDescs = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.GetEndpointsRequest)) & memoryBuffer.Encode(req) & memoryBuffer.EncodeUAString(this.GetEndpointString()) & memoryBuffer.EncodeUAString(localeIDs) & memoryBuffer.Encode(0U);
                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 431U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                endpointDescs = new EndpointDescription[(int)v];
                for (int index = 0; index < v & flag3; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out endpointDescs[index]);
                }

                return !flag3 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode FindServers(
          out ApplicationDescription[] results,
          string[] localeIDs)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.FindServersRequest)) & memoryBuffer.Encode(req) & memoryBuffer.EncodeUAString(this.GetEndpointString()) & memoryBuffer.EncodeUAString(localeIDs) & memoryBuffer.Encode(0U);
                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 425U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new ApplicationDescription[(int)v];
                for (int index = 0; index < v & flag3; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                return !flag3 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        private StatusCode MessageSecureAndSend(SLChannel config, MemoryBuffer respBuf)
        {
            int num1 = (int)config.TL.RemoteConfig.RecvBufferSize - 24 - 1024;
            int num2 = (respBuf.Position - 24 + num1 - 1) / num1;
            if (num2 > 1 && num2 > config.TL.RemoteConfig.MaxChunkCount)
            {
                return StatusCode.BadEncodingLimitsExceeded;
            }

            if (num2 > 1)
            {
                MemoryBuffer memoryBuffer = new MemoryBuffer(num1 + 24 + 1024);
                for (int index = 0; index < num2; ++index)
                {
                    bool flag = index == num2 - 1;
                    memoryBuffer.Rewind();
                    int num3 = index * num1;
                    int Size = flag ? respBuf.Position - 24 - num3 : num1;
                    memoryBuffer.Append(respBuf.Buffer, 0, 24);
                    if (index > 0)
                    {
                        memoryBuffer.Encode(config.LocalSequence.SequenceNumber, 16);
                        ++config.LocalSequence.SequenceNumber;
                    }
                    memoryBuffer.Buffer[3] = flag ? (byte)70 : (byte)67;
                    memoryBuffer.Append(respBuf.Buffer, 24 + num3, Size);
                    if (config.MessageSecurityMode == MessageSecurityMode.None)
                    {
                        this.MarkPositionAsSize(memoryBuffer);
                    }
                    else
                    {
                        StatusCode statusCode = UASecurity.SecureSymmetric(memoryBuffer, 16, config.LocalKeysets[0], config.RemoteKeysets[0], config.SecurityPolicy, config.MessageSecurityMode);
                        if (!Types.StatusCodeIsGood((uint)statusCode))
                        {
                            return statusCode;
                        }
                    }
                    this.tcp.Client.Send(memoryBuffer.Buffer, memoryBuffer.Position, SocketFlags.None);
                    Interlocked.Add(ref this.totalBytesSent, memoryBuffer.Position);
                }
            }
            else
            {
                if (config.MessageSecurityMode == MessageSecurityMode.None)
                {
                    this.MarkPositionAsSize(respBuf);
                }
                else
                {
                    StatusCode statusCode = UASecurity.SecureSymmetric(respBuf, 16, config.LocalKeysets[0], config.RemoteKeysets[0], config.SecurityPolicy, config.MessageSecurityMode);
                    if (!Types.StatusCodeIsGood((uint)statusCode))
                    {
                        return statusCode;
                    }
                }
                if (!this.IsConnected)
                {
                    return StatusCode.BadConnectionClosed;
                }

                this.tcp.Client.Send(respBuf.Buffer, respBuf.Position, SocketFlags.None);
                Interlocked.Add(ref this.totalBytesSent, respBuf.Position);
            }
            return StatusCode.Good;
        }

        public StatusCode Connect()
        {
            this.cs = new Semaphore(1, 1);
            try
            {
                this.cs.WaitOne();
                if (this.IsConnected)
                {
                    int num = (int)this.Disconnect();
                }
                this.totalBytesSent = 0L;
                this.totalBytesRecv = 0L;
                try
                {
                    this.tcp = new TcpClient(this.Target, this.Port);
                }
                catch (SocketException)
                {
                    return StatusCode.BadConnectionRejected;
                }
                this.csDispatching = new Semaphore(1, 1);
                this.csWaitForSecure = new Semaphore(0, 1);
                this.nextRequestHandle = 0U;
                this.tcp.LingerState = new LingerOption(true, this.Timeout);
                this.tcp.NoDelay = true;
                this.tcp.Client.NoDelay = true;
                this.config = new SLChannel();
                this.config.Endpoint = this.tcp.Client.RemoteEndPoint as IPEndPoint;
                this.config.SLState = ConnectionState.Opening;
                this.recvQueue = new Dictionary<Tuple<uint, uint>, Client.RecvHandler>();
                this.recvNotify = new Dictionary<Tuple<uint, uint>, ManualResetEvent>();
                this.recvPendingRequests = new HashSet<Tuple<uint, uint>>();
                this.publishReqs = new HashSet<uint>();
                this.recvHandlerStatus = StatusCode.Good;
                this.threadAbort = false;
                this.thread = new Thread(new ParameterizedThreadStart(Client.ThreadTarget));
                this.thread.Start(this);
                StatusCode statusCode = this.SendHello();
                return statusCode > StatusCode.Good ? statusCode : statusCode;
            }
            finally
            {
                this.cs.Release();
            }
        }

        private StatusCode SendHello()
        {
            MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
            this.config.TL = new TLConnection();
            this.config.TL.LocalConfig = new TLConfiguration()
            {
                ProtocolVersion = 0U,
                SendBufferSize = 65536U,
                RecvBufferSize = 65536U,
                MaxMessageSize = (uint)this.MaximumMessageSize,
                MaxChunkCount = 1337U + (uint)(this.MaximumMessageSize + ushort.MaxValue) / 65536U
            };
            if (!(true & memoryBuffer.Encode(1179403592U) & memoryBuffer.Encode(0U) & memoryBuffer.Encode(this.config.TL.LocalConfig.ProtocolVersion) & memoryBuffer.Encode(this.config.TL.LocalConfig.RecvBufferSize) & memoryBuffer.Encode(this.config.TL.LocalConfig.SendBufferSize) & memoryBuffer.Encode(this.config.TL.LocalConfig.MaxMessageSize) & memoryBuffer.Encode(this.config.TL.LocalConfig.MaxChunkCount) & memoryBuffer.EncodeUAString(this.GetEndpointString())))
            {
                return StatusCode.BadEncodingLimitsExceeded;
            }

            this.MarkPositionAsSize(memoryBuffer);
            Tuple<uint, uint> key1 = new Tuple<uint, uint>(4932417U, 0U);
            ManualResetEvent manualResetEvent = new ManualResetEvent(false);
            lock (this.recvNotify)
            {
                this.recvNotify[key1] = manualResetEvent;
            }

            this.tcp.Client.Send(memoryBuffer.Buffer, memoryBuffer.Position, SocketFlags.None);
            Interlocked.Add(ref this.totalBytesSent, memoryBuffer.Position);
            bool flag = manualResetEvent.WaitOne(this.Timeout * 1000);
            lock (this.recvNotify)
            {
                this.recvNotify.Remove(key1);
            }

            if (this.recvHandlerStatus > StatusCode.Good)
            {
                return this.recvHandlerStatus;
            }

            if (!flag)
            {
                return StatusCode.BadRequestTimeout;
            }

            Client.RecvHandler recvHandler;
            lock (this.recvQueue)
            {
                Tuple<uint, uint> key2 = new Tuple<uint, uint>(4932417U, 0U);
                if (!this.recvQueue.TryGetValue(key2, out recvHandler))
                {
                    return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                }

                this.recvQueue.Remove(key2);
            }
            this.config.TL.RemoteConfig = new TLConfiguration();
            if (!recvHandler.RecvBuf.Decode(out this.config.TL.RemoteConfig.ProtocolVersion) || !recvHandler.RecvBuf.Decode(out this.config.TL.RemoteConfig.RecvBufferSize) || (!recvHandler.RecvBuf.Decode(out this.config.TL.RemoteConfig.SendBufferSize) || !recvHandler.RecvBuf.Decode(out this.config.TL.RemoteConfig.MaxMessageSize)) || !recvHandler.RecvBuf.Decode(out this.config.TL.RemoteConfig.MaxChunkCount))
            {
                return StatusCode.BadDecodingError;
            }

            this.MaximumMessageSize = (int)Math.Min(config.TL.RemoteConfig.MaxMessageSize, MaximumMessageSize);
            return StatusCode.Good;
        }

        private string GetEndpointString()
        {
            return !string.IsNullOrWhiteSpace(this.Path) ? string.Format("opc.tcp://{0}:{1}/{2}", Target, this.config.Endpoint.Port.ToString(), Path) : string.Format("opc.tcp://{0}:{1}", Target, this.config.Endpoint.Port.ToString());
        }

        protected void MarkPositionAsSize(MemoryBuffer mb, uint position)
        {
            int position1 = mb.Position;
            mb.Position = 4;
            mb.Encode(position);
            mb.Position = position1;
        }

        protected void MarkPositionAsSize(MemoryBuffer mb)
        {
            uint position = (uint)mb.Position;
            mb.Position = 4;
            mb.Encode(position);
            mb.Position = (int)position;
        }

        public void Dispose()
        {
            int num = (int)this.Disconnect();
        }

        public StatusCode Disconnect()
        {
            this.nextPublish = false;
            if (this.renewTimer != null)
            {
                try
                {
                    this.cs.WaitOne();
                    this.renewTimer.Stop();
                }
                finally
                {
                    this.cs.Release();
                }
                this.renewTimer = null;
            }
            if (this.thread != null)
            {
                if (this.config.SessionIdToken != null)
                {
                    int num1 = (int)this.CloseSession();
                }
                if (this.config.ChannelID > 0U)
                {
                    int num2 = (int)this.CloseSecureChannel();
                }
                this.threadAbort = true;
                this.thread.Join();
                this.thread = null;
            }
            return StatusCode.Good;
        }

        private void CloseConnection()
        {
            try
            {
                if (this.tcp == null)
                {
                    return;
                }

                this.tcp.Client.Shutdown(SocketShutdown.Both);
                this.tcp.Close();
                if (this.OnConnectionClosed != null)
                {
                    this.OnConnectionClosed();
                }
            }
            finally
            {
                this.tcp = null;
            }
        }

        ~Client()
        {
            this.Dispose();
        }

        private static void ThreadTarget(object args)
        {
            (args as Client).ThreadTarget();
        }

        private void ThreadTarget()
        {
            Socket client = this.tcp.Client;
            int num1 = 0;
            byte[] numArray1 = new byte[this.MaximumMessageSize];
            while (this.IsConnected && !this.threadAbort)
            {
                if (client.Poll(100000, SelectMode.SelectRead))
                {
                    int size = this.MaximumMessageSize - num1;
                    if (size > 0)
                    {
                        int num2;
                        try
                        {
                            num2 = client.Receive(numArray1, num1, size, SocketFlags.None);
                        }
                        catch
                        {
                            break;
                        }
                        if (num2 != 0)
                        {
                            Interlocked.Add(ref this.totalBytesRecv, num2);
                            num1 += num2;
                            if (num1 <= this.MaximumMessageSize)
                            {
                                while (num1 > 0)
                                {
                                    this.csDispatching.WaitOne();
                                    int sourceIndex = -1;
                                    try
                                    {
                                        sourceIndex = this.Consume(this.config, new MemoryBuffer(numArray1, num1));
                                    }
                                    catch
                                    {
                                        this.recvHandlerStatus = StatusCode.BadDecodingError;
                                        sourceIndex = -1;
                                    }
                                    finally
                                    {
                                        this.csDispatching.Release();
                                    }
                                    switch (sourceIndex)
                                    {
                                        case -1:
                                            num1 = -1;
                                            goto label_20;
                                        case 0:
                                            goto label_20;
                                        default:
                                            if (sourceIndex >= num1)
                                            {
                                                if (sourceIndex > num1)
                                                {
                                                    throw new Exception(string.Format("Consumed {0} but accumulated message size is {1}", sourceIndex, num1));
                                                }

                                                num1 = 0;
                                            }
                                            else
                                            {
                                                int length = num1 - sourceIndex;
                                                byte[] numArray2 = new byte[this.MaximumMessageSize];
                                                Array.Copy(numArray1, sourceIndex, numArray2, 0, length);
                                                numArray1 = numArray2;
                                                num1 = length;
                                            }
                                            continue;
                                    }
                                }
                            label_20:
                                this.CheckPostCall();
                                if (num1 == -1 || num1 >= this.MaximumMessageSize)
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
                    else
                    {
                        break;
                    }
                }
            }
            this.CloseConnection();
            lock (this.recvNotify)
            {
                foreach (KeyValuePair<Tuple<uint, uint>, ManualResetEvent> keyValuePair in this.recvNotify)
                {
                    keyValuePair.Value.Set();
                }
            }
            lock (this.recvQueue)
            {
                foreach (KeyValuePair<Tuple<uint, uint>, ManualResetEvent> keyValuePair in this.recvNotify)
                {
                    keyValuePair.Value.Set();
                }
            }
        }

        private void CheckPostCall()
        {
            if (!this.nextPublish || this.PublishRequest() == StatusCode.GoodCallAgain)
            {
                return;
            }

            this.nextPublish = false;
        }

        private bool ChunkReconstruct(MemoryBuffer buf, List<uint> chunkLengths)
        {
            if (buf.Capacity < 24)
            {
                return false;
            }

            uint position = 0;
            for (int index = 0; index < chunkLengths.Count; ++index)
            {
                if (index == 0)
                {
                    position += chunkLengths[index];
                }
                else
                {
                    if (chunkLengths[index] < 24U)
                    {
                        return false;
                    }

                    position += chunkLengths[index] - 24U;
                }
            }
            uint num1 = 0;
            uint num2 = 24;
            for (int index = 0; index < chunkLengths.Count; ++index)
            {
                uint chunkLength = chunkLengths[index];
                if (index > 0)
                {
                    Array.Copy(buf.Buffer, (int)num1 + 24, buf.Buffer, (int)num2, (int)chunkLength - 24);
                }

                num1 += chunkLength;
                num2 += chunkLength - 24U;
            }
            buf.Buffer[3] = 70;
            this.MarkPositionAsSize(buf, position);
            return true;
        }

        private MemoryBuffer ChunkReconstructSecured(
          MemoryBuffer buf,
          List<uint> chunkLengths,
          SLChannel config)
        {
            if (buf.Capacity < 24)
            {
                return null;
            }

            MemoryBuffer recvBuf = new MemoryBuffer(buf.Capacity);
            MemoryBuffer mb = new MemoryBuffer(buf.Capacity);
            uint num1 = 0;
            int num2 = 0;
            for (int index = 0; index < chunkLengths.Count; ++index)
            {
                uint chunkLength = chunkLengths[index];
                Array.Copy(buf.Buffer, num1, recvBuf.Buffer, 0L, (int)chunkLength);
                recvBuf.Position = 3;
                if (!Types.StatusCodeIsGood((uint)UASecurity.UnsecureSymmetric(recvBuf, config.TokenID, config.PrevTokenID, 16, config.LocalKeysets[0], config.RemoteKeysets, config.SecurityPolicy, config.MessageSecurityMode, out int decrSize)))
                {
                    return null;
                }

                num2 += decrSize;
                if (index == 0)
                {
                    Array.Copy(recvBuf.Buffer, 0, mb.Buffer, 0, 24);
                    mb.Buffer[3] = 70;
                    mb.Position = 24;
                }
                mb.Append(recvBuf.Buffer, 24, decrSize - 24);
                num1 += chunkLength;
            }
            this.MarkPositionAsSize(mb);
            return mb;
        }

        private List<uint> ChunkCalculateSizes(MemoryBuffer memBuf)
        {
            List<uint> uintList = new List<uint>();
            uint num1 = 0;
            bool flag;
            do
            {
                if (memBuf.Capacity >= num1 + 24U)
                {
                    byte num2 = memBuf.Buffer[(int)num1 + 3];
                    if (num2 == 67 || num2 == 70)
                    {
                        flag = num2 == 70;
                        if (memBuf.Decode(out uint v, (int)num1 + 4))
                        {
                            uintList.Add(v);
                            num1 += v;
                            if (memBuf.Capacity < num1)
                            {
                                goto label_7;
                            }
                        }
                        else
                        {
                            goto label_5;
                        }
                    }
                    else
                    {
                        goto label_3;
                    }
                }
                else
                {
                    goto label_1;
                }
            }
            while (!flag);
            goto label_10;
        label_1:
            return null;
        label_3:
            return null;
        label_5:
            return null;
        label_7:
            return null;
        label_10:
            return uintList;
        }

        private int Consume(SLChannel config, MemoryBuffer recvBuf)
        {
            if (recvBuf.Capacity < 8)
            {
                return 0;
            }

            uint num1 = (uint)(recvBuf.Buffer[0] | recvBuf.Buffer[1] << 8 | recvBuf.Buffer[2] << 16);
            uint num2;
            if (recvBuf.Buffer[3] == 70)
            {
                num2 = (uint)(recvBuf.Buffer[4] | recvBuf.Buffer[5] << 8 | recvBuf.Buffer[6] << 16 | recvBuf.Buffer[7] << 24);
                if (config != null && config.TL != null && num2 > config.TL.LocalConfig.MaxMessageSize)
                {
                    this.recvHandlerStatus = StatusCode.BadResponseTooLarge;
                    return -1;
                }
                if (num2 > recvBuf.Capacity)
                {
                    return 0;
                }

                if ((num1 == 4674381U || num1 == 5196867U) && (config.MessageSecurityMode > MessageSecurityMode.None && config.LocalKeysets != null && config.RemoteKeysets != null))
                {
                    int position = recvBuf.Position;
                    recvBuf.Position = 3;
                    uint code = (uint)UASecurity.UnsecureSymmetric(recvBuf, config.TokenID, config.PrevTokenID, 16, config.LocalKeysets[0], config.RemoteKeysets, config.SecurityPolicy, config.MessageSecurityMode, out int decrSize);
                    recvBuf.Position = position;
                    if (!Types.StatusCodeIsGood(code))
                    {
                        return -1;
                    }
                }
            }
            else if (recvBuf.Buffer[3] == 67)
            {
                List<uint> sizes = this.ChunkCalculateSizes(recvBuf);
                if (sizes == null)
                {
                    return 0;
                }

                if (config.MessageSecurityMode > MessageSecurityMode.None && config.LocalKeysets != null && config.RemoteKeysets != null)
                {
                    recvBuf = this.ChunkReconstructSecured(recvBuf, sizes, config);
                    if (recvBuf == null)
                    {
                        this.recvHandlerStatus = StatusCode.BadMessageNotAvailable;
                        return -1;
                    }
                }
                else if (!this.ChunkReconstruct(recvBuf, sizes))
                {
                    this.recvHandlerStatus = StatusCode.BadMessageNotAvailable;
                    return -1;
                }
                num2 = 0U;
                foreach (uint num3 in sizes)
                {
                    num2 += num3;
                }

                if (num2 > recvBuf.Capacity)
                {
                    return 0;
                }
            }
            else
            {
                this.recvHandlerStatus = StatusCode.BadMessageNotAvailable;
                return -1;
            }
            recvBuf.Position = 8;
            switch (num1)
            {
                case 4932417:
                    lock (this.recvQueue)
                    {
                        Tuple<uint, uint> key = new Tuple<uint, uint>(num1, 0U);
                        this.recvQueue[key] = new Client.RecvHandler()
                        {
                            Header = null,
                            RecvBuf = recvBuf.Duplicate(),
                            Type = NodeId.Zero
                        };
                        if (this.recvNotify.TryGetValue(key, out ManualResetEvent manualResetEvent))
                        {
                            manualResetEvent.Set();
                            break;
                        }
                        break;
                    }
                case 5132367:
                    ManualResetEvent manualResetEvent1 = null;
                    lock (this.recvQueue)
                    {
                        Tuple<uint, uint> key = new Tuple<uint, uint>(num1, 0U);
                        this.recvQueue[key] = new Client.RecvHandler()
                        {
                            Header = null,
                            RecvBuf = recvBuf.Duplicate(),
                            Type = NodeId.Zero
                        };
                        if (this.recvNotify.TryGetValue(key, out manualResetEvent1))
                        {
                            manualResetEvent1.Set();
                        }
                    }
                    if (manualResetEvent1 != null)
                    {
                        this.csWaitForSecure.WaitOne();
                        break;
                    }
                    break;
                case 5395013:
                    this.recvHandlerStatus = StatusCode.BadCommunicationError;
                    try
                    {
                        if (recvBuf.Decode(out uint v))
                        {
                            this.recvHandlerStatus = (StatusCode)v;
                        }
                    }
                    catch
                    {
                    }
                    return -1;
                default:
                    uint v1;
                    bool flag = true & recvBuf.Decode(out uint _) & recvBuf.Decode(out uint _) & recvBuf.Decode(out v1) & recvBuf.Decode(out uint _);
                    config.RemoteSequence.SequenceNumber = v1;
                    NodeId id;
                    ResponseHeader resp;
                    if (!(flag & recvBuf.Decode(out id) & recvBuf.Decode(out resp)))
                    {
                        this.recvHandlerStatus = StatusCode.BadDecodingError;
                        return -1;
                    }
                    if (this.publishReqs.Contains(resp.RequestHandle))
                    {
                        this.ConsumeNotification(new Client.RecvHandler()
                        {
                            Header = resp,
                            RecvBuf = recvBuf.Duplicate(),
                            Type = id
                        });
                        this.publishReqs.Remove(resp.RequestHandle);
                        this.nextPublish = true;
                    }
                    else
                    {
                        lock (this.recvQueue)
                        {
                            Tuple<uint, uint> key = new Tuple<uint, uint>(num1, resp.RequestHandle);
                            this.recvQueue[key] = new Client.RecvHandler()
                            {
                                Header = resp,
                                RecvBuf = recvBuf.Duplicate(),
                                Type = id
                            };
                            if (this.recvNotify.TryGetValue(key, out ManualResetEvent manualResetEvent2))
                            {
                                manualResetEvent2.Set();
                            }
                        }
                    }
                    break;
            }
            return (int)num2;
        }

        public StatusCode ActivateSession(
          object identityToken,
          string[] localeIDs,
          SecurityPolicy? userIdentitySecurityPolicy = null)
        {
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.ActivateSessionRequest)) & memoryBuffer.Encode(req);
                bool flag2;
                if (this.config.MessageSecurityMode == MessageSecurityMode.None)
                {
                    flag2 = flag1 & memoryBuffer.EncodeUAString((string)null) & memoryBuffer.EncodeUAByteString(null);
                }
                else
                {
                    if (this.config.RemoteNonce == null)
                    {
                        return StatusCode.BadSessionClosed;
                    }

                    byte[] certificateString = this.config.RemoteCertificateString;
                    byte[] array = new byte[certificateString.Length + this.config.RemoteNonce.Length];
                    Array.Copy(certificateString, 0, array, 0, certificateString.Length);
                    Array.Copy(config.RemoteNonce, 0, array, certificateString.Length, this.config.RemoteNonce.Length);
                    byte[] str = UASecurity.RsaPkcs15Sha_Sign(new ArraySegment<byte>(array), ApplicationPrivateKey, this.config.SecurityPolicy);
                    flag2 = (this.config.SecurityPolicy != SecurityPolicy.Basic256Sha256 ? flag1 & memoryBuffer.EncodeUAString("http://www.w3.org/2000/09/xmldsig#rsa-sha1") : flag1 & memoryBuffer.EncodeUAString("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")) & memoryBuffer.EncodeUAByteString(str);
                }
                bool flag3 = flag2 & memoryBuffer.Encode(0U) & memoryBuffer.EncodeUAString(localeIDs);
                bool flag4;
                switch (identityToken)
                {
                    case UserIdentityAnonymousToken _:
                        bool flag5 = flag3 & memoryBuffer.Encode(new NodeId(UAConst.AnonymousIdentityToken_Encoding_DefaultBinary)) & memoryBuffer.Encode((byte)1);
                        int position1 = memoryBuffer.Position;
                        flag4 = flag5 & memoryBuffer.Encode(0U) & memoryBuffer.EncodeUAString((identityToken as UserIdentityAnonymousToken).PolicyId) & memoryBuffer.Encode((uint)(memoryBuffer.Position - position1 - 4), position1);
                        break;
                    case UserIdentityUsernameToken _:
                        bool flag6 = flag3 & memoryBuffer.Encode(new NodeId(UAConst.UserNameIdentityToken_Encoding_DefaultBinary)) & memoryBuffer.Encode((byte)1);
                        int position2 = memoryBuffer.Position;
                        bool flag7 = flag6 & memoryBuffer.Encode(0U) & memoryBuffer.EncodeUAString((identityToken as UserIdentityUsernameToken).PolicyId) & memoryBuffer.EncodeUAString((identityToken as UserIdentityUsernameToken).Username);
                        bool flag8;
                        try
                        {
                            byte[] passwordHash = (identityToken as UserIdentityUsernameToken).PasswordHash;
                            X509Certificate2 remoteCertificate1 = this.config.RemoteCertificate;
                            SecurityPolicy? nullable = userIdentitySecurityPolicy;
                            int num1 = nullable.HasValue ? (int)nullable.GetValueOrDefault() : (int)this.config.SecurityPolicy;
                            int position3 = 4 + passwordHash.Length;
                            int sigSize = this.config.RemoteNonce == null ? 0 : this.config.RemoteNonce.Length;
                            int paddingSize = UASecurity.CalculatePaddingSize(remoteCertificate1, (SecurityPolicy)num1, position3, sigSize);
                            byte[] randomBytes = UASecurity.GenerateRandomBytes(paddingSize);
                            byte[] array = new byte[4 + passwordHash.Length + paddingSize + (this.config.RemoteNonce == null ? 0 : this.config.RemoteNonce.Length)];
                            int num2 = passwordHash.Length + (this.config.RemoteNonce == null ? 0 : this.config.RemoteNonce.Length);
                            array[0] = (byte)(num2 & byte.MaxValue);
                            array[1] = (byte)(num2 >> 8 & byte.MaxValue);
                            array[2] = (byte)(num2 >> 16 & byte.MaxValue);
                            array[3] = (byte)(num2 >> 24 & byte.MaxValue);
                            Array.Copy(passwordHash, 0, array, 4, passwordHash.Length);
                            int destinationIndex = 4 + passwordHash.Length;
                            if (this.config.RemoteNonce != null)
                            {
                                Array.Copy(config.RemoteNonce, 0, array, destinationIndex, this.config.RemoteNonce.Length);
                                destinationIndex += this.config.RemoteNonce.Length;
                            }
                            Array.Copy(randomBytes, 0, array, destinationIndex, randomBytes.Length);
                            int num3 = destinationIndex + randomBytes.Length;
                            ArraySegment<byte> data = new ArraySegment<byte>(array);
                            X509Certificate2 remoteCertificate2 = this.config.RemoteCertificate;
                            nullable = userIdentitySecurityPolicy;
                            int num4 = nullable.HasValue ? (int)nullable.GetValueOrDefault() : (int)this.config.SecurityPolicy;
                            byte[] str = UASecurity.RsaPkcs15Sha_Encrypt(data, remoteCertificate2, (SecurityPolicy)num4);
                            flag8 = flag7 & memoryBuffer.EncodeUAByteString(str) & memoryBuffer.EncodeUAString((identityToken as UserIdentityUsernameToken).Algorithm);
                        }
                        catch
                        {
                            return StatusCode.BadIdentityTokenInvalid;
                        }
                        flag4 = flag8 & memoryBuffer.Encode((uint)(memoryBuffer.Position - position2 - 4), position2);
                        break;
                    default:
                        throw new Exception(string.Format("Identity token of type {0} is not supported", identityToken.GetType().ToString()));
                }
                bool flag9 = flag4 & memoryBuffer.EncodeUAString((string)null) & memoryBuffer.EncodeUAByteString(null);
                if (!flag9)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag10 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag10)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 470U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag11 = flag9 & recvHandler.RecvBuf.DecodeUAByteString(out byte[] str1);
                this.config.RemoteNonce = str1;
                if (!flag11)
                {
                    return StatusCode.BadDecodingError;
                }

                if (this.renewTimer != null)
                {
                    this.renewTimer.Stop();
                }

                this.renewTimer = new System.Timers.Timer(0.7 * config.TokenLifetime);
                this.renewTimer.Elapsed += (sender, e) =>
               {
                   StatusCode statusCode = this.RenewSecureChannel();
                   if (Types.StatusCodeIsGood((uint)statusCode))
                   {
                       return;
                   }

                   this.recvHandlerStatus = statusCode;
                   int num = (int)this.Disconnect();
               };
                this.renewTimer.Start();
                return StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode CreateSession(
          ApplicationDescription appDesc,
          string sessionName,
          int requestedSessionTimeout)
        {
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.CreateSessionRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(appDesc) & memoryBuffer.EncodeUAString((string)null) & memoryBuffer.EncodeUAString(this.GetEndpointString()) & memoryBuffer.EncodeUAString(sessionName) & memoryBuffer.EncodeUAByteString(this.config.LocalNonce);
                bool flag2 = (this.ApplicationCertificate != null ? flag1 & memoryBuffer.EncodeUAByteString(this.ApplicationCertificate.Export(X509ContentType.Cert)) : flag1 & memoryBuffer.EncodeUAByteString(null)) & memoryBuffer.Encode((double)(10000 * requestedSessionTimeout)) & memoryBuffer.Encode((uint)this.MaximumMessageSize);
                if (!flag2)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag3 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag3)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 464U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag4 = flag2 & recvHandler.RecvBuf.Decode(out NodeId id1) & recvHandler.RecvBuf.Decode(out NodeId id2) & recvHandler.RecvBuf.Decode(out double _);
                this.config.SessionIdToken = id1;
                this.config.AuthToken = id2;
                bool flag5 = flag4 & recvHandler.RecvBuf.DecodeUAByteString(out byte[] str1) & recvHandler.RecvBuf.DecodeUAByteString(out byte[] str2);
                this.config.RemoteNonce = str1;
                try
                {
                    this.config.RemoteCertificate = new X509Certificate2(str2);
                }
                catch
                {
                    return StatusCode.BadSecurityChecksFailed;
                }
                return !flag5 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode CloseSession()
        {
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.CloseSessionRequest)) & memoryBuffer.Encode(req);
                bool v = false;
                bool flag2 = flag1 & memoryBuffer.Encode(v);
                if (!flag2)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag3 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag3)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 476U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                return !flag2 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode Read(ReadValueId[] Ids, out DataValue[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.ReadRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(0.0) & memoryBuffer.Encode(2U) & memoryBuffer.Encode((uint)Ids.Length);
                for (int index = 0; index < Ids.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(Ids[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 634U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new DataValue[(int)v];
                for (int index = 0; index < v & flag3; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                if (!flag3)
                {
                    return StatusCode.BadDecodingError;
                }

                return v != Ids.Length ? StatusCode.GoodResultsMayBeIncomplete : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode Write(WriteValue[] Ids, out uint[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.WriteRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode((uint)Ids.Length);
                for (int index = 0; index < Ids.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(Ids[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 676U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new uint[(int)v];
                for (int index = 0; index < v & flag3; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                if (!flag3)
                {
                    return StatusCode.BadDecodingError;
                }

                return v != Ids.Length ? StatusCode.GoodResultsMayBeIncomplete : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode AddNodes(AddNodesItem[] addNodesItems, out AddNodesResult[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.AddNodesRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode((uint)addNodesItems.Length);
                for (int index = 0; index < addNodesItems.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(addNodesItems[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 491U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new AddNodesResult[(int)v];
                for (int index = 0; index < v & flag3; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                if (!flag3)
                {
                    return StatusCode.BadDecodingError;
                }

                return v != addNodesItems.Length ? StatusCode.GoodResultsMayBeIncomplete : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode DeleteNodes(DeleteNodesItem[] deleteNodesItems, out uint[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.DeleteNodesRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode((uint)deleteNodesItems.Length);
                for (int index = 0; index < deleteNodesItems.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(deleteNodesItems[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 503U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new uint[(int)v];
                for (int index = 0; index < v & flag3; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                if (!flag3)
                {
                    return StatusCode.BadDecodingError;
                }

                return v != deleteNodesItems.Length ? StatusCode.GoodResultsMayBeIncomplete : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode AddReferences(
          AddReferencesItem[] addReferencesItems,
          out uint[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.AddReferencesRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode((uint)addReferencesItems.Length);
                for (int index = 0; index < addReferencesItems.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(addReferencesItems[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 497U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new uint[(int)v];
                for (int index = 0; index < v & flag3; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                if (!flag3)
                {
                    return StatusCode.BadDecodingError;
                }

                return v != addReferencesItems.Length ? StatusCode.GoodResultsMayBeIncomplete : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode DeleteReferences(
          DeleteReferencesItem[] deleteReferencesItems,
          out uint[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.DeleteReferencesRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode((uint)deleteReferencesItems.Length);
                for (int index = 0; index < deleteReferencesItems.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(deleteReferencesItems[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 509U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new uint[(int)v];
                for (int index = 0; index < v & flag3; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                if (!flag3)
                {
                    return StatusCode.BadDecodingError;
                }

                return v != deleteReferencesItems.Length ? StatusCode.GoodResultsMayBeIncomplete : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode Browse(
          BrowseDescription[] requests,
          uint requestedMaxReferencesPerNode,
          out BrowseResult[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.BrowseRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(NodeId.Zero) & memoryBuffer.Encode(0UL) & memoryBuffer.Encode(0U) & memoryBuffer.Encode(requestedMaxReferencesPerNode) & memoryBuffer.Encode((uint)requests.Length);
                for (int index = 0; index < requests.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(requests[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 530U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v1);
                results = new BrowseResult[(int)v1];
                for (int index1 = 0; index1 < v1 & flag3; ++index1)
                {
                    flag3 = flag3 & recvHandler.RecvBuf.Decode(out uint v2) & recvHandler.RecvBuf.DecodeUAByteString(out byte[] str) & recvHandler.RecvBuf.Decode(out uint v3);
                    if (v3 == uint.MaxValue)
                    {
                        v3 = 0U;
                    }

                    ReferenceDescription[] Refs = new ReferenceDescription[(int)v3];
                    for (int index2 = 0; index2 < Refs.Length; ++index2)
                    {
                        flag3 &= recvHandler.RecvBuf.Decode(out Refs[index2]);
                    }

                    results[index1] = new BrowseResult(v2, str, Refs);
                }
                if (!flag3)
                {
                    return StatusCode.BadDecodingError;
                }

                return v1 != requests.Length ? StatusCode.GoodResultsMayBeIncomplete : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode BrowseNext(
          IList<byte[]> contPoints,
          bool releaseContinuationPoints,
          out BrowseResult[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.BrowseNextRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(releaseContinuationPoints) & memoryBuffer.Encode((uint)contPoints.Count);
                for (int index = 0; index < contPoints.Count; ++index)
                {
                    flag1 &= memoryBuffer.EncodeUAByteString(contPoints[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 536U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                if (!releaseContinuationPoints)
                {
                    flag1 &= recvHandler.RecvBuf.Decode(out uint v1);
                    results = new BrowseResult[(int)v1];
                    for (int index1 = 0; index1 < v1 & flag1; ++index1)
                    {
                        flag1 = flag1 & recvHandler.RecvBuf.Decode(out uint v2) & recvHandler.RecvBuf.DecodeUAByteString(out byte[] str) & recvHandler.RecvBuf.Decode(out uint v3);
                        ReferenceDescription[] Refs = new ReferenceDescription[(int)v3];
                        for (int index2 = 0; index2 < Refs.Length; ++index2)
                        {
                            flag1 &= recvHandler.RecvBuf.Decode(out Refs[index2]);
                        }

                        results[index1] = new BrowseResult(v2, str, Refs);
                    }
                    if (!flag1)
                    {
                        return StatusCode.BadDecodingError;
                    }

                    if (v1 != contPoints.Count)
                    {
                        return StatusCode.GoodResultsMayBeIncomplete;
                    }
                }
                return !flag1 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode HistoryRead(
          object historyReadDetails,
          TimestampsToReturn timestampsToReturn,
          bool releaseContinuationPoints,
          HistoryReadValueId[] requests,
          out HistoryReadResult[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer1 = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer1, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer1.Encode(new NodeId(RequestCode.HistoryReadRequest)) & memoryBuffer1.Encode(req);
                bool flag2;
                switch (historyReadDetails)
                {
                    case ReadRawModifiedDetails _:
                        bool flag3 = flag1 & memoryBuffer1.Encode(new NodeId(UAConst.ReadRawModifiedDetails_Encoding_DefaultBinary)) & memoryBuffer1.Encode((byte)1);
                        int position1 = memoryBuffer1.Position;
                        flag2 = flag3 & memoryBuffer1.Encode(0U) & memoryBuffer1.Encode((historyReadDetails as ReadRawModifiedDetails).IsReadModified) & memoryBuffer1.Encode((historyReadDetails as ReadRawModifiedDetails).StartTime.ToFileTime()) & memoryBuffer1.Encode((historyReadDetails as ReadRawModifiedDetails).EndTime.ToFileTime()) & memoryBuffer1.Encode((historyReadDetails as ReadRawModifiedDetails).NumValuesPerNode) & memoryBuffer1.Encode((historyReadDetails as ReadRawModifiedDetails).ReturnBounds) & memoryBuffer1.Encode((uint)(memoryBuffer1.Position - position1 - 4), position1);
                        break;
                    case ReadProcessedDetails _:
                        bool flag4 = flag1 & memoryBuffer1.Encode(new NodeId(UAConst.ReadProcessedDetails_Encoding_DefaultBinary)) & memoryBuffer1.Encode((byte)1);
                        int position2 = memoryBuffer1.Position;
                        int num1 = flag4 & memoryBuffer1.Encode(0U) ? 1 : 0;
                        MemoryBuffer memoryBuffer2 = memoryBuffer1;
                        DateTime dateTime = (historyReadDetails as ReadProcessedDetails).StartTime;
                        long fileTime1 = dateTime.ToFileTime();
                        int num2 = memoryBuffer2.Encode(fileTime1) ? 1 : 0;
                        int num3 = (num1 & num2) != 0 ? 1 : 0;
                        MemoryBuffer memoryBuffer3 = memoryBuffer1;
                        dateTime = (historyReadDetails as ReadProcessedDetails).EndTime;
                        long fileTime2 = dateTime.ToFileTime();
                        int num4 = memoryBuffer3.Encode(fileTime2) ? 1 : 0;
                        bool flag5 = (num3 & num4) != 0 & memoryBuffer1.Encode((historyReadDetails as ReadProcessedDetails).ProcessingInterval) & memoryBuffer1.Encode((uint)(historyReadDetails as ReadProcessedDetails).AggregateTypes.Length);
                        for (int index = 0; index < (historyReadDetails as ReadProcessedDetails).AggregateTypes.Length; ++index)
                        {
                            flag5 &= memoryBuffer1.Encode((historyReadDetails as ReadProcessedDetails).AggregateTypes[index]);
                        }

                        flag2 = flag5 & memoryBuffer1.Encode((historyReadDetails as ReadProcessedDetails).Configuration) & memoryBuffer1.Encode((uint)(memoryBuffer1.Position - position2 - 4), position2);
                        break;
                    case ReadAtTimeDetails _:
                        bool flag6 = flag1 & memoryBuffer1.Encode(new NodeId(UAConst.ReadAtTimeDetails_Encoding_DefaultBinary)) & memoryBuffer1.Encode((byte)1);
                        int position3 = memoryBuffer1.Position;
                        bool flag7 = flag6 & memoryBuffer1.Encode(0U) & memoryBuffer1.Encode((historyReadDetails as ReadAtTimeDetails).ReqTimes.Length);
                        for (int index = 0; index < (historyReadDetails as ReadAtTimeDetails).ReqTimes.Length; ++index)
                        {
                            flag7 &= memoryBuffer1.Encode((historyReadDetails as ReadAtTimeDetails).ReqTimes[index].ToFileTime());
                        }

                        flag2 = flag7 & memoryBuffer1.Encode((historyReadDetails as ReadAtTimeDetails).UseSimpleBounds) & memoryBuffer1.Encode((uint)(memoryBuffer1.Position - position3 - 4), position3);
                        break;
                    case ReadEventDetails _:
                        bool flag8 = flag1 & memoryBuffer1.Encode(new NodeId(UAConst.ReadEventDetails_Encoding_DefaultBinary)) & memoryBuffer1.Encode((byte)1);
                        int position4 = memoryBuffer1.Position;
                        flag2 = flag8 & memoryBuffer1.Encode(0U) & memoryBuffer1.Encode((historyReadDetails as ReadEventDetails).NumValuesPerNode) & memoryBuffer1.Encode((historyReadDetails as ReadEventDetails).StartTime.ToFileTime()) & memoryBuffer1.Encode((historyReadDetails as ReadEventDetails).EndTime.ToFileTime()) & memoryBuffer1.Encode(new EventFilter((historyReadDetails as ReadEventDetails).SelectClauses, null), false) & memoryBuffer1.Encode((uint)(memoryBuffer1.Position - position4 - 4), position4);
                        break;
                    default:
                        throw new Exception(string.Format("History read details of type {0} is not supported", historyReadDetails.GetType().ToString()));
                }
                bool flag9 = flag2 & memoryBuffer1.Encode((uint)timestampsToReturn) & memoryBuffer1.Encode(releaseContinuationPoints) & memoryBuffer1.Encode((uint)requests.Length);
                for (int index = 0; index < requests.Length; ++index)
                {
                    flag9 = flag9 & memoryBuffer1.Encode(requests[index].NodeId) & memoryBuffer1.EncodeUAString(requests[index].IndexRange) & memoryBuffer1.Encode(requests[index].DataEncoding) & memoryBuffer1.EncodeUAByteString(requests[index].ContinuationPoint);
                }

                if (!flag9)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer1);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag10 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag10)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 667U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                if (!releaseContinuationPoints)
                {
                    flag9 &= recvHandler.RecvBuf.Decode(out uint v1);
                    results = new HistoryReadResult[(int)v1];
                    for (int index1 = 0; index1 < v1 & flag9; ++index1)
                    {
                        bool flag11 = flag9 & recvHandler.RecvBuf.Decode(out uint v2) & recvHandler.RecvBuf.DecodeUAByteString(out byte[] str) & recvHandler.RecvBuf.Decode(out NodeId id) & recvHandler.RecvBuf.Decode(out byte v3);
                        if (v3 != 1)
                        {
                            return StatusCode.BadDataEncodingInvalid;
                        }

                        bool flag12 = flag11 & recvHandler.RecvBuf.Decode(out uint _);
                        if (id.EqualsNumeric(0, 658U))
                        {
                            flag9 = flag12 & recvHandler.RecvBuf.Decode(out uint v4);
                            DataValue[] Values = new DataValue[(int)v4];
                            for (int index2 = 0; index2 < v4; ++index2)
                            {
                                flag9 &= recvHandler.RecvBuf.Decode(out Values[index2]);
                            }

                            results[index1] = new HistoryReadResult(v2, str, Values);
                        }
                        else
                        {
                            if (!id.EqualsNumeric(0, 661U))
                            {
                                return StatusCode.BadDataEncodingInvalid;
                            }

                            flag9 = flag12 & recvHandler.RecvBuf.Decode(out uint v4);
                            DataValue[] Values = new DataValue[(int)v4];
                            for (int index2 = 0; flag9 && index2 < v4; ++index2)
                            {
                                flag9 &= recvHandler.RecvBuf.Decode(out uint v5);
                                object[] objArray = new object[(int)v5];
                                for (int index3 = 0; flag9 && index3 < v5; ++index3)
                                {
                                    flag9 &= recvHandler.RecvBuf.VariantDecode(out objArray[index3]);
                                }

                                Values[index2] = new DataValue(objArray, new uint?(), new DateTime?(), new DateTime?());
                            }
                            results[index1] = new HistoryReadResult(v2, str, Values);
                        }
                    }
                    if (!flag9)
                    {
                        return StatusCode.BadDecodingError;
                    }

                    if (v1 != requests.Length)
                    {
                        return StatusCode.GoodResultsMayBeIncomplete;
                    }
                }
                return !flag9 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode HistoryUpdate(HistoryUpdateData[] requests, out uint[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.HistoryUpdateRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode((uint)requests.Length);
                for (int index1 = 0; index1 < requests.Length; ++index1)
                {
                    bool flag2 = flag1 & memoryBuffer.Encode(new NodeId(UAConst.UpdateDataDetails_Encoding_DefaultBinary)) & memoryBuffer.Encode((byte)1);
                    int position = memoryBuffer.Position;
                    bool flag3 = flag2 & memoryBuffer.Encode(0U) & memoryBuffer.Encode(requests[index1].NodeId) & memoryBuffer.Encode((uint)requests[index1].PerformUpdate) & memoryBuffer.Encode((uint)requests[index1].Value.Length);
                    for (int index2 = 0; index2 < requests[index1].Value.Length; ++index2)
                    {
                        flag3 &= memoryBuffer.Encode(requests[index1].Value[index2]);
                    }

                    flag1 = flag3 & memoryBuffer.Encode((uint)(memoryBuffer.Position - position - 4), position);
                }
                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag4 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag4)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 703U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag5 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new uint[(int)v];
                for (int index = 0; index < v & flag5; ++index)
                {
                    flag5 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                if (v != requests.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                return !flag5 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode TranslateBrowsePathsToNodeIds(
          BrowsePath[] requests,
          out BrowsePathResult[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.TranslateBrowsePathsToNodeIdsRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode((uint)requests.Length);
                for (int index = 0; index < requests.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(requests[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 557U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new BrowsePathResult[(int)v];
                for (int index = 0; index < v & flag3; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                if (v != requests.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                return !flag3 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode Call(CallMethodRequest[] requests, out CallMethodResult[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.CallRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode((uint)requests.Length);
                for (int index1 = 0; index1 < requests.Length; ++index1)
                {
                    flag1 = flag1 & memoryBuffer.Encode(requests[index1].ObjectId) & memoryBuffer.Encode(requests[index1].MethodId) & memoryBuffer.Encode((uint)requests[index1].InputArguments.Length);
                    for (int index2 = 0; index2 < requests[index1].InputArguments.Length; ++index2)
                    {
                        flag1 &= memoryBuffer.VariantEncode(requests[index1].InputArguments[index2]);
                    }
                }
                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 715U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v1);
                results = new CallMethodResult[(int)v1];
                for (int index1 = 0; index1 < v1 & flag3; ++index1)
                {
                    bool flag4 = flag3 & recvHandler.RecvBuf.Decode(out uint v2) & recvHandler.RecvBuf.Decode(out uint v3);
                    if (v3 == uint.MaxValue)
                    {
                        v3 = 0U;
                    }

                    uint[] Results = new uint[(int)v3];
                    for (int index2 = 0; index2 < v3; ++index2)
                    {
                        flag4 &= recvHandler.RecvBuf.Decode(out Results[index2]);
                    }

                    bool flag5 = flag4 & recvHandler.RecvBuf.Decode(out uint v4);
                    if (v4 > 0U && v4 != uint.MaxValue)
                    {
                        return StatusCode.BadTypeMismatch;
                    }

                    flag3 = flag5 & recvHandler.RecvBuf.Decode(out uint v5);
                    if (v5 == uint.MaxValue)
                    {
                        v5 = 0U;
                    }

                    object[] Outputs = new object[(int)v5];
                    for (int index2 = 0; index2 < v5; ++index2)
                    {
                        flag3 &= recvHandler.RecvBuf.VariantDecode(out Outputs[index2]);
                    }

                    results[index1] = new CallMethodResult(v2, Results, Outputs);
                }
                if (v1 != requests.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                return !flag3 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode CreateSubscription(
          double RequestedPublishingInterval,
          uint MaxNotificationsPerPublish,
          bool PublishingEnabled,
          byte Priority,
          out uint result)
        {
            result = uint.MaxValue;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.CreateSubscriptionRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(RequestedPublishingInterval) & memoryBuffer.Encode(uint.MaxValue) & memoryBuffer.Encode(uint.MaxValue) & memoryBuffer.Encode(MaxNotificationsPerPublish) & memoryBuffer.Encode(PublishingEnabled) & memoryBuffer.Encode(Priority);
                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 790U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                if (!(flag1 & recvHandler.RecvBuf.Decode(out result) & recvHandler.RecvBuf.Decode(out double _) & recvHandler.RecvBuf.Decode(out uint _) & recvHandler.RecvBuf.Decode(out uint _)))
                {
                    return StatusCode.BadDecodingError;
                }
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
            lock (this.publishReqs)
            {
                if (this.publishReqs.Count > 0)
                {
                    return StatusCode.Good;
                }
            }
            return this.PublishRequest();
        }

        public StatusCode ModifySubscription(
          uint subscriptionId,
          double RequestedPublishingInterval,
          uint MaxNotificationsPerPublish,
          bool PublishingEnabled,
          byte Priority,
          out uint result)
        {
            result = 0U;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.ModifySubscriptionRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(subscriptionId) & memoryBuffer.Encode(RequestedPublishingInterval) & memoryBuffer.Encode(uint.MaxValue) & memoryBuffer.Encode(uint.MaxValue) & memoryBuffer.Encode(MaxNotificationsPerPublish) & memoryBuffer.Encode(PublishingEnabled) & memoryBuffer.Encode(Priority);
                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 796U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                if (!(flag1 & recvHandler.RecvBuf.Decode(out double _) & recvHandler.RecvBuf.Decode(out uint _) & recvHandler.RecvBuf.Decode(out uint _)))
                {
                    return StatusCode.BadDecodingError;
                }

                result = recvHandler.Header.ServiceResult;
                return StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode DeleteSubscription(uint[] subscriptionIds, out uint[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.DeleteSubscriptionsRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode((uint)subscriptionIds.Length);
                for (int index = 0; index < subscriptionIds.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(subscriptionIds[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 850U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new uint[(int)v];
                for (int index = 0; index < v; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                return !flag3 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode SetPublishingMode(
          bool PublishingEnabled,
          uint[] requestIds,
          out uint[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.SetPublishingModeRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(PublishingEnabled) & memoryBuffer.Encode((uint)requestIds.Length);
                for (int index = 0; index < requestIds.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(requestIds[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 802U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new uint[(int)v];
                for (int index = 0; index < v; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                return !flag3 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode CreateMonitoredItems(
          uint subscriptionId,
          TimestampsToReturn timestampsToReturn,
          MonitoredItemCreateRequest[] requests,
          out MonitoredItemCreateResult[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.CreateMonitoredItemsRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(subscriptionId) & memoryBuffer.Encode((uint)timestampsToReturn) & memoryBuffer.Encode((uint)requests.Length);
                for (int index = 0; index < requests.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(requests[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 754U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new MonitoredItemCreateResult[(int)v];
                for (int index = 0; index < v; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                return !flag3 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode ModifyMonitoredItems(
          uint subscriptionId,
          TimestampsToReturn timestampsToReturn,
          MonitoredItemModifyRequest[] requests,
          out MonitoredItemModifyResult[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.ModifyMonitoredItemsRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(subscriptionId) & memoryBuffer.Encode((uint)timestampsToReturn) & memoryBuffer.Encode((uint)requests.Length);
                for (int index = 0; index < requests.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(requests[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 766U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new MonitoredItemModifyResult[(int)v];
                for (int index = 0; index < v; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                return !flag3 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        public StatusCode DeleteMonitoredItems(
          uint subscriptionId,
          uint[] monitorIds,
          out uint[] results)
        {
            results = null;
            try
            {
                this.cs.WaitOne();
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                bool flag1 = true & memoryBuffer.Encode(new NodeId(RequestCode.DeleteMonitoredItemsRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(subscriptionId) & memoryBuffer.Encode((uint)monitorIds.Length);
                for (int index = 0; index < monitorIds.Length; ++index)
                {
                    flag1 &= memoryBuffer.Encode(monitorIds[index]);
                }

                if (!flag1)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                Tuple<uint, uint> key = new Tuple<uint, uint>(4674381U, req.RequestHandle);
                ManualResetEvent manualResetEvent = new ManualResetEvent(false);
                lock (this.recvNotify)
                {
                    this.recvNotify[key] = manualResetEvent;
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                if (statusCode2 > StatusCode.Good)
                {
                    return statusCode2;
                }

                bool flag2 = manualResetEvent.WaitOne(this.Timeout * 1000);
                lock (this.recvNotify)
                {
                    this.recvNotify.Remove(key);
                }

                if (!flag2)
                {
                    return StatusCode.BadRequestTimeout;
                }

                Client.RecvHandler recvHandler = null;
                lock (this.recvQueue)
                {
                    if (!this.recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return this.recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : this.recvHandlerStatus;
                    }

                    this.recvQueue.Remove(key);
                }
                if (!recvHandler.Type.EqualsNumeric(0, 784U))
                {
                    return StatusCode.BadUnknownResponse;
                }

                bool flag3 = flag1 & recvHandler.RecvBuf.Decode(out uint v);
                results = new uint[(int)v];
                for (int index = 0; index < v; ++index)
                {
                    flag3 &= recvHandler.RecvBuf.Decode(out results[index]);
                }

                return !flag3 ? StatusCode.BadDecodingError : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
                this.CheckPostCall();
            }
        }

        private void ConsumeNotification(Client.RecvHandler recvHandler)
        {
            bool flag1 = true & recvHandler.RecvBuf.Decode(out uint v1) & recvHandler.RecvBuf.Decode(out uint v2);
            uint v3;
            for (int index = 0; index < v2; ++index)
            {
                flag1 &= recvHandler.RecvBuf.Decode(out v3);
            }

            bool flag2 = flag1 & recvHandler.RecvBuf.Decode(out bool _) & recvHandler.RecvBuf.Decode(out v3) & recvHandler.RecvBuf.Decode(out ulong v4);
            DateTimeOffset dateTimeOffset;
            try
            {
                dateTimeOffset = DateTimeOffset.FromFileTime((long)v4);
            }
            catch
            {
                dateTimeOffset = DateTimeOffset.MinValue;
            }
            bool flag3 = flag2 & recvHandler.RecvBuf.Decode(out uint v5);
            for (int index1 = 0; flag3 && index1 < v5; ++index1)
            {
                bool flag4 = flag3 & recvHandler.RecvBuf.Decode(out NodeId id) & recvHandler.RecvBuf.Decode(out byte v6) & recvHandler.RecvBuf.Decode(out uint _);
                if (v6 != 1)
                {
                    break;
                }

                if (id.EqualsNumeric(0, 811U))
                {
                    flag3 = flag4 & recvHandler.RecvBuf.Decode(out uint v7);
                    if (v7 > 0U)
                    {
                        DataValue[] notifications = new DataValue[(int)v7];
                        uint[] clientHandles = new uint[(int)v7];
                        for (int index2 = 0; flag3 && index2 < v7; ++index2)
                        {
                            flag3 = flag3 & recvHandler.RecvBuf.Decode(out clientHandles[index2]) & recvHandler.RecvBuf.Decode(out notifications[index2]);
                        }

                        if (!flag3)
                        {
                            break;
                        }

                        this.NotifyDataChangeNotifications(v1, clientHandles, notifications);
                    }
                }
                else
                {
                    if (!id.EqualsNumeric(0, 916U))
                    {
                        break;
                    }

                    flag3 = flag4 & recvHandler.RecvBuf.Decode(out uint v7);
                    if (v7 > 0U)
                    {
                        object[][] notifications = new object[(int)v7][];
                        uint[] clientHandles = new uint[(int)v7];
                        for (int index2 = 0; flag3 && index2 < v7; ++index2)
                        {
                            flag3 = flag3 & recvHandler.RecvBuf.Decode(out clientHandles[index2]) & recvHandler.RecvBuf.Decode(out uint v8);
                            notifications[index2] = new object[(int)v8];
                            for (int index3 = 0; flag3 && index3 < v8; ++index3)
                            {
                                flag3 &= recvHandler.RecvBuf.VariantDecode(out notifications[index2][index3]);
                            }
                        }
                        if (!flag3)
                        {
                            break;
                        }

                        this.NotifyEventNotifications(v1, clientHandles, notifications);
                    }
                }
            }
        }

        public virtual void NotifyEventNotifications(
          uint subscrId,
          uint[] clientHandles,
          object[][] notifications)
        {
        }

        public virtual void NotifyDataChangeNotifications(
          uint subscrId,
          uint[] clientHandles,
          DataValue[] notifications)
        {
        }

        private StatusCode PublishRequest()
        {
            if (!this.cs.WaitOne(0))
            {
                return StatusCode.GoodCallAgain;
            }

            try
            {
                MemoryBuffer memoryBuffer = new MemoryBuffer(this.MaximumMessageSize);
                StatusCode statusCode1 = this.EncodeMessageHeader(memoryBuffer, false, MessageType.Message);
                if (statusCode1 > StatusCode.Good)
                {
                    return statusCode1;
                }

                RequestHeader req = new RequestHeader()
                {
                    RequestHandle = this.nextRequestHandle++,
                    Timestamp = DateTime.Now,
                    AuthToken = this.config.AuthToken
                };
                if (!(true & memoryBuffer.Encode(new NodeId(RequestCode.PublishRequest)) & memoryBuffer.Encode(req) & memoryBuffer.Encode(0U)))
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                lock (this.publishReqs)
                {
                    this.publishReqs.Add(req.RequestHandle);
                }

                StatusCode statusCode2 = this.MessageSecureAndSend(this.config, memoryBuffer);
                return statusCode2 > StatusCode.Good ? statusCode2 : StatusCode.Good;
            }
            finally
            {
                this.cs.Release();
            }
        }

        public delegate void ConnectionClosed();

        private class RecvHandler
        {
            public MemoryBuffer RecvBuf { get; set; }

            public NodeId Type { get; set; }

            public ResponseHeader Header { get; set; }
        }
    }
}
