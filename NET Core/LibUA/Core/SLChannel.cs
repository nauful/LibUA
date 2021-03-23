
// Type: LibUA.Core.SLChannel



using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LibUA.Core
{
    public class SLChannel
    {
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

        public uint TokenLifetime { get; set; }

        public DateTimeOffset TokenCreatedAt { get; set; }

        public uint? PrevChannelID { get; set; }

        public uint? PrevTokenID { get; set; }

        public NodeId AuthToken { get; set; }

        public NodeId SessionIdToken { get; set; }

        public byte[] LocalNonce { get; set; }

        public byte[] RemoteNonce { get; set; }

        public byte[] SessionIssuedNonce { get; set; }

        public SLChannel.Keyset[] LocalKeysets { get; set; }

        public SLChannel.Keyset[] RemoteKeysets { get; set; }

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
    }
}
