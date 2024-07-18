using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LibUA
{
    namespace Core
    {
        public class SLChannel
        {
            public class Keyset
            {
                public byte[] SymSignKey { get; protected set; }
                public byte[] SymEncKey { get; protected set; }
                public byte[] SymIV { get; protected set; }

                public Keyset(byte[] SymSignKey, byte[] SymEncKey, byte[] SymIV)
                {
                    this.SymSignKey = SymSignKey;
                    this.SymEncKey = SymEncKey;
                    this.SymIV = SymIV;
                }

                public Keyset()
                {
                    this.SymSignKey = null;
                    this.SymEncKey = null;
                    this.SymIV = null;
                }
            }

            public int ID { get; set; }
            public ConnectionState SLState { get; set; }

            public X509Certificate2 RemoteCertificate { get; set; }
            public byte[] RemoteCertificateString { get; set; }

            public object Session { get; set; }

            public TLConnection TL { get; set; }
            public IPEndPoint Endpoint { get; set; }

            public SLSequence LocalSequence { get; set; }
            public SLSequence RemoteSequence { get; set; }
            public SecurityPolicy SecurityPolicy { get; set; }
            public MessageSecurityMode MessageSecurityMode { get; set; }

            public uint ChannelID { get; set; }
            public uint TokenID { get; set; }
            public UInt32 TokenLifetime { get; set; }
            public DateTimeOffset TokenCreatedAt { get; set; }

            public uint? PrevChannelID { get; set; }
            public uint? PrevTokenID { get; set; }

            public NodeId AuthToken { get; set; }
            public NodeId SessionIdToken { get; set; }

            public byte[] LocalNonce { get; set; }
            public byte[] RemoteNonce { get; set; }
            public byte[] SessionIssuedNonce { get; set; }

            public Keyset[] LocalKeysets { get; set; }
            public Keyset[] RemoteKeysets { get; set; }
        }
    }
}
