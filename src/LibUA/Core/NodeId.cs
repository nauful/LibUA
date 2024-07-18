using System;
using System.Linq;

namespace LibUA
{
    namespace Core
    {
        public class NodeId : IEquatable<NodeId>
        {
            public static readonly NodeId Zero = new NodeId(0, 0);

            public UInt16 NamespaceIndex
            {
                get; protected set;
            }

            public UInt32 NumericIdentifier
            {
                get; protected set;
            }

            private object _ObjectIdentifier;
            public byte[] ByteStringIdentifier
            {
                get => (byte[])_ObjectIdentifier;
                protected set => _ObjectIdentifier = (object)value;
            }

            public string StringIdentifier
            {
                get => (string)_ObjectIdentifier;
                protected set => _ObjectIdentifier = (object)value;
            }

            public NodeIdNetType IdType
            {
                get; protected set;
            }

            public static NodeId TryParse(string str)
            {
                int splitIdx = str.IndexOf(';');
                if (splitIdx == -1) { return null; }

                var nsStr = str.Substring(0, splitIdx);
                if (!nsStr.ToLowerInvariant().StartsWith("ns="))
                {
                    return null;
                }

                if (!ushort.TryParse(nsStr.Substring(3), out ushort nsIdx))
                {
                    return null;
                }

                var vstr = str.Substring(splitIdx + 1);
                var vstrType = vstr.ToLowerInvariant();
                if (vstrType.StartsWith("s="))
                {
                    return new NodeId(nsIdx, vstr.Substring(2));
                }
                else if (vstrType.StartsWith("i="))
                {
                    if (!UInt32.TryParse(vstrType.Substring(2), out uint idx))
                    {
                        return null;
                    }

                    return new NodeId(nsIdx, idx);
                }

                return null;
            }

            public NodeId(UInt32 NumericIdentifier)
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

            public NodeId(UInt16 NamespaceIndex, UInt32 NumericIdentifier)
            {
                this.NamespaceIndex = NamespaceIndex;
                this.NumericIdentifier = NumericIdentifier;
                this.IdType = NodeIdNetType.Numeric;
            }

            public NodeId(UInt16 NamespaceIndex, string StringIdentifier)
            {
                this.NamespaceIndex = NamespaceIndex;
                this.StringIdentifier = StringIdentifier ?? string.Empty;
                this.IdType = NodeIdNetType.String;
            }

            public NodeId(UInt16 NamespaceIndex, byte[] ByteStringIdentifier, NodeIdNetType IdType)
            {
                this.NamespaceIndex = NamespaceIndex;
                this.ByteStringIdentifier = ByteStringIdentifier;
                this.IdType = IdType;
            }

            public override string ToString()
            {
                if (IdType == NodeIdNetType.String)
                {
                    return string.Format("ns={0};s={1}", NamespaceIndex, StringIdentifier);
                }
                else if (IdType == NodeIdNetType.ByteString)
                {
                    return string.Format("ns={0};bs=0x{1}", NamespaceIndex, string.Join("", ByteStringIdentifier.Select(v => v.ToString("X2"))));
                }
                else if (IdType == NodeIdNetType.Guid)
                {
                    return string.Format("ns={0};guid=0x{1}", NamespaceIndex, string.Join("", ByteStringIdentifier.Select(v => v.ToString("X2"))));
                }

                return string.Format("ns={0};i={1}", NamespaceIndex, NumericIdentifier);
            }

            public override int GetHashCode()
            {
                uint res = 2166136261;
                res ^= NamespaceIndex;
                res *= 16777619;

                if (IdType == NodeIdNetType.Numeric)
                {
                    res ^= (uint)NumericIdentifier;
                }
                else if (IdType == NodeIdNetType.ByteString || IdType == NodeIdNetType.Guid)
                {
                    for (int i = 0; i < ByteStringIdentifier.Length; i++)
                    {
                        res = (res * 33) + ByteStringIdentifier[i];
                    }
                }
                else
                {
                    res ^= (uint)StringIdentifier.GetHashCode();
                }

                res *= 16777619;
                return (int)(res & 0x7FFFFFFF);
            }

            public bool IsNull()
            {
                // OPC 10000-3: Address Space Model
                // 8.2.4 Identifier value
                // A canonical null NodeId has an IdType equal to Numeric, a NamespaceIndex equal to 0 and an
                // Identifier equal to 0.
                //
                // In addition to the canonical null NodeId the alternative values defined in Table 23 shall be
                // considered a null NodeId.
                // IdType        NamespaceIndex        Null Value
                // String           0                  A null or Empty String(“”)
                // Guid             0                  A Guid initialised with zeros(e.g. 00000000-0000-0000-0000-000000)
                // Opaque           0                  A null or Empty ByteString
                return NamespaceIndex == 0 && (
                       (IdType == NodeIdNetType.Numeric && NumericIdentifier == 0)
                    || (IdType == NodeIdNetType.String && string.IsNullOrEmpty(StringIdentifier))
                    || (IdType == NodeIdNetType.Guid && (ByteStringIdentifier is null || Guid.Empty == new Guid(ByteStringIdentifier)))
                    || (IdType == NodeIdNetType.ByteString && (ByteStringIdentifier is null || ByteStringIdentifier.Length == 0))
                    );
            }

            public bool EqualsNumeric(UInt16 ns, UInt32 addr)
            {
                if (IdType != NodeIdNetType.Numeric) { return false; }

                if (NamespaceIndex != ns) { return false; }
                if (NumericIdentifier != addr) { return false; }

                return true;
            }

            public bool Equals(NodeId other)
            {
                if (NamespaceIndex != other.NamespaceIndex)
                {
                    return false;
                }

                if (this.IsNull() && other.IsNull())
                {
                    return true;
                }
                if (IdType != other.IdType)
                {
                    return false;
                }

                return IdType == NodeIdNetType.Numeric ? NumericIdentifier == other.NumericIdentifier
                    : IdType == NodeIdNetType.String ? String.Equals(StringIdentifier, other.StringIdentifier, StringComparison.Ordinal)
                    : EqualByteString(ByteStringIdentifier, other.ByteStringIdentifier);
            }

            private bool EqualByteString(byte[] a, byte[] b)
            {
                if (a == null && b == null)
                {
                    return true;
                }
                if (a == null || b == null)
                {
                    return false;
                }
                if (a.Length.Equals(b.Length))
                {
                    for (int i = 0; i < a.Length; i++)
                    {
                        if (!byte.Equals(a[i], b[i]))
                        {
                            return false;
                        }
                    }
                    return true;
                }
                return false;
            }

            public override bool Equals(object other)
            {
                if (other is NodeId) { return Equals(other as NodeId); }
                return false;
            }
        }
    }
}
