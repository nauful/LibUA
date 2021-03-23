
// Type: LibUA.Core.NodeId



using System;
using System.Collections.Generic;
using System.Linq;

namespace LibUA.Core
{
    public partial class NodeId : IEquatable<NodeId>
    {
        public static readonly NodeId Zero = new NodeId(0, 0U);

        public ushort NamespaceIndex { get; protected set; }

        public uint NumericIdentifier { get; protected set; }

        public byte[] ByteStringIdentifier { get; protected set; }

        public string StringIdentifier { get; protected set; }

        public NodeIdNetType IdType { get; protected set; }

        public static implicit operator NodeId(string s)
        {
            return NodeId.TryParse(s);
        }

        public static NodeId TryParse(string str)
        {
            int length = str.IndexOf(';');
            if (length == -1)
            {
                return null;
            }

            string str1 = str.Substring(0, length);
            if (!str1.ToLowerInvariant().StartsWith("ns=") || !ushort.TryParse(str1.Substring(3), out ushort result1))
            {
                return null;
            }

            string str2 = str.Substring(length + 1);
            string lowerInvariant = str2.ToLowerInvariant();
            if (lowerInvariant.StartsWith("s="))
            {
                return new NodeId(result1, str2.Substring(2));
            }

            return lowerInvariant.StartsWith("i=") && uint.TryParse(lowerInvariant.Substring(2), out uint result2) ? new NodeId(result1, result2) : null;
        }

        public NodeId(uint NumericIdentifier)
        {
            this.NamespaceIndex = 0;
            this.NumericIdentifier = NumericIdentifier;
            this.IdType = NodeIdNetType.Numeric;
        }

        public NodeId(UAConst NumericIdentifier)
        {
            this.NamespaceIndex = 0;
            this.NumericIdentifier = (uint)NumericIdentifier;
            this.IdType = NodeIdNetType.Numeric;
        }

        public NodeId(RequestCode NumericIdentifier)
        {
            this.NamespaceIndex = 0;
            this.NumericIdentifier = (uint)NumericIdentifier;
            this.IdType = NodeIdNetType.Numeric;
        }

        public NodeId(ushort NamespaceIndex, uint NumericIdentifier)
        {
            this.NamespaceIndex = NamespaceIndex;
            this.NumericIdentifier = NumericIdentifier;
            this.IdType = NodeIdNetType.Numeric;
        }

        public NodeId(ushort NamespaceIndex, string StringIdentifier)
        {
            this.NamespaceIndex = NamespaceIndex;
            this.StringIdentifier = StringIdentifier ?? string.Empty;
            this.IdType = NodeIdNetType.String;
        }

        public NodeId(ushort NamespaceIndex, byte[] ByteStringIdentifier, NodeIdNetType IdType)
        {
            this.NamespaceIndex = NamespaceIndex;
            this.ByteStringIdentifier = ByteStringIdentifier;
            this.IdType = IdType;
        }

        public override string ToString()
        {
            if (this.IdType == NodeIdNetType.String)
            {
                return string.Format("ns={0};s={1}", NamespaceIndex, StringIdentifier);
            }

            if (this.IdType == NodeIdNetType.ByteString)
            {
                return string.Format("ns={0};bs=0x{1}", NamespaceIndex, string.Join("", ((IEnumerable<byte>)this.ByteStringIdentifier).Select<byte, string>(v => v.ToString("X2"))));
            }

            return this.IdType == NodeIdNetType.Guid ? string.Format("ns={0};guid=0x{1}", NamespaceIndex, string.Join("", ((IEnumerable<byte>)this.ByteStringIdentifier).Select<byte, string>(v => v.ToString("X2")))) : string.Format("ns={0};i={1}", NamespaceIndex, NumericIdentifier);
        }

        public override int GetHashCode()
        {
            uint num = (2166136261U ^ NamespaceIndex) * 16777619U;
            if (this.IdType == NodeIdNetType.Numeric)
            {
                num ^= this.NumericIdentifier;
            }
            else if (this.IdType == NodeIdNetType.ByteString || this.IdType == NodeIdNetType.Guid)
            {
                for (int index = 0; index < this.ByteStringIdentifier.Length; ++index)
                {
                    num = num * 33U + this.ByteStringIdentifier[index];
                }
            }
            else
            {
                num ^= (uint)this.StringIdentifier.GetHashCode();
            }

            return (int)(num * 16777619U) & int.MaxValue;
        }

        public bool EqualsNumeric(ushort ns, uint addr)
        {
            return (uint)this.IdType <= 0U && NamespaceIndex == ns && (int)this.NumericIdentifier == (int)addr;
        }

        public bool Equals(NodeId other)
        {
            return NamespaceIndex == other.NamespaceIndex && this.IdType == other.IdType && (this.IdType == NodeIdNetType.Numeric ? (int)this.NumericIdentifier == (int)other.NumericIdentifier : (this.IdType == NodeIdNetType.String ? this.StringIdentifier == other.StringIdentifier : this.EqualByteString(this.ByteStringIdentifier, other.ByteStringIdentifier)));
        }

        private bool EqualByteString(byte[] a, byte[] b)
        {
            if (a == null && b == null)
            {
                return true;
            }

            if (a == null || b == null || !a.Length.Equals(b.Length))
            {
                return false;
            }

            for (int index = 0; index < a.Length; ++index)
            {
                if (!object.Equals(a[index], b[index]))
                {
                    return false;
                }
            }
            return true;
        }

        public override bool Equals(object other)
        {
            return other is NodeId && this.Equals(other as NodeId);
        }
    }
}
