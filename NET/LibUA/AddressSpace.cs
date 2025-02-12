using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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

            public byte[] ByteStringIdentifier
            {
                get; protected set;
            }

            public string StringIdentifier
            {
                get; protected set;
            }

            public NodeIdNetType IdType
            {
                get; protected set;
            }

            public static NodeId TryParse(string str)
            {
                ushort nsIdx = 0;

                int splitIdx = str.IndexOf(';');
                if (splitIdx != -1)
                {
                    var nsStr = str.Substring(0, splitIdx);
                    if (!nsStr.StartsWith("ns=", StringComparison.InvariantCultureIgnoreCase))
                    {
                        return null;
                    }

                    if (!ushort.TryParse(nsStr.Substring(3).ToString(), out nsIdx))
                    {
                        return null;
                    }
                    splitIdx++;
                }
                else
                {
                    splitIdx = 0;
                }

                var vstr = str.Substring(splitIdx);
                if (vstr.StartsWith("s=", StringComparison.InvariantCultureIgnoreCase))
                {
                    return new NodeId(nsIdx, vstr.Substring(2).ToString());
                }
                else if (vstr.StartsWith("i=", StringComparison.InvariantCultureIgnoreCase))
                {
                    if (!UInt32.TryParse(vstr.Substring(2).ToString(), out uint idx))
                    {
                        return null;
                    }

                    return new NodeId(nsIdx, idx);
                }
                else if (vstr.StartsWith("b=0x", StringComparison.InvariantCultureIgnoreCase))
                {
                    //Note: This encoding is not in the standard but should work
                    //fine in combination with Base64 encoding below
                    vstr = vstr.Substring(4);

                    // Convert hex string to byte array
                    byte[] byteArray = new byte[vstr.Length / 2];
                    for (int i = 0; i < vstr.Length/2; ++i)
                    {
                        if (!byte.TryParse(vstr.Substring(2 * i, 2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out byteArray[i]))
                        {
                            return null;
                        }
                    }

                    return new NodeId(nsIdx, byteArray, NodeIdNetType.ByteString);
                }
                else if (vstr.StartsWith("b=", StringComparison.InvariantCultureIgnoreCase))
                {
                    //Convert from base 64 encoded string
                    vstr = vstr.Substring(2);
                    byte[] byteArray = Convert.FromBase64String(vstr);
                    return new NodeId(nsIdx, byteArray, NodeIdNetType.ByteString);
                }
                else if (vstr.StartsWith("g=", StringComparison.InvariantCultureIgnoreCase))
                {
                    vstr = vstr.Substring(2);
                    if (Guid.TryParse(vstr.ToString(), out Guid guid))
                        return new NodeId(nsIdx, guid.ToByteArray(), NodeIdNetType.Guid);
                    else
                        return null;
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
                if (NamespaceIndex == 0)
                {
                    if (IdType == NodeIdNetType.String)
                    {
                        return $"s={StringIdentifier}";
                    }
                    else if (IdType == NodeIdNetType.ByteString)
                    {
                        return $"b={Convert.ToBase64String(ByteStringIdentifier)}";
                    }
                    else if (IdType == NodeIdNetType.Guid)
                    {
                        var guid = new Guid(ByteStringIdentifier);
                        return $"g={guid}";
                    }

                    return $"i={NumericIdentifier}";
                }
                else
                {
                    if (IdType == NodeIdNetType.String)
                    {
                        return $"ns={NamespaceIndex};s={StringIdentifier}";
                    }
                    else if (IdType == NodeIdNetType.ByteString)
                    {
                        return $"ns={NamespaceIndex};b={Convert.ToBase64String(ByteStringIdentifier)}";
                    }
                    else if (IdType == NodeIdNetType.Guid)
                    {
                        var guid = new Guid(ByteStringIdentifier);
                        return $"ns={NamespaceIndex};g={guid}";
                    }

                    return $"ns={NamespaceIndex};i={NumericIdentifier}";
                }
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

                if (IdType != other.IdType)
                {
                    return false;
                }

                return IdType == NodeIdNetType.Numeric ?
                    NumericIdentifier == other.NumericIdentifier :
                    StringIdentifier == other.StringIdentifier;
            }

            public override bool Equals(object other)
            {
                if (other is NodeId) { return Equals(other as NodeId); }
                return false;
            }
        }

        public interface IDataSource
        {
            object GetValue(NodeId nodeId);
            void SetValue(NodeId nodeId, object newValue);
        }

        public class Node
        {
            public List<ReferenceNode> References
            {
                get; protected set;
            }

            public NodeId Id
            {
                get; protected set;
            }

            public NodeClass Class
            {
                get; protected set;
            }

            public QualifiedName BrowseName
            {
                get; protected set;
            }

            public LocalizedText DisplayName
            {
                get; protected set;
            }

            public LocalizedText Description
            {
                get; protected set;
            }

            public UInt32 WriteMask
            {
                get; protected set;
            }

            public UInt32 UserWriteMask
            {
                get; protected set;
            }

            public Node(NodeId Id, NodeClass Class, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask)
            {
                this.Id = Id;
                this.Class = Class;
                this.BrowseName = BrowseName;
                this.DisplayName = DisplayName;
                this.Description = Description;
                this.WriteMask = WriteMask;
                this.UserWriteMask = UserWriteMask;

                this.References = new List<ReferenceNode>();
            }

            public NodeClass GetNodeClass()
            {
                NodeClass nodeClass = NodeClass.Unspecified;

                if (this is NodeObject) { nodeClass = NodeClass.Object; }
                else if (this is NodeVariable) { nodeClass = NodeClass.Variable; }
                else if (this is NodeMethod) { nodeClass = NodeClass.Method; }
                else if (this is NodeObjectType) { nodeClass = NodeClass.ObjectType; }
                else if (this is NodeVariableType) { nodeClass = NodeClass.VariableType; }
                else if (this is NodeReferenceType) { nodeClass = NodeClass.ReferenceType; }
                else if (this is NodeDataType) { nodeClass = NodeClass.DataType; }
                else if (this is NodeView) { nodeClass = NodeClass.View; }

                return nodeClass;
            }
        }

        public class NodeObject : Node
        {
            public byte EventNotifier
            {
                get; protected set;
            }

            public NodeObject(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, byte EventNotifier)
                : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
            {
                this.EventNotifier = EventNotifier;
            }
        }

        public class NodeObjectType : Node
        {
            public bool IsAbstract
            {
                get; protected set;
            }

            public NodeObjectType(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool IsAbstract)
                : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
            {
                this.IsAbstract = IsAbstract;
            }
        }

        public class NodeVariable : Node
        {
            public object Value
            {
                get; set;
            }

            public NodeId DataType
            {
                get; protected set;
            }

            public Core.AccessLevel AccessLevel
            {
                get; protected set;
            }

            public Core.AccessLevel UserAccessLevel
            {
                get; protected set;
            }

            public double MinimumResamplingInterval
            {
                get; protected set;
            }

            public bool IsHistorizing
            {
                get; protected set;
            }

            public int ValueRank
            {
                get; protected set;
            }

            public NodeVariable(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, Core.AccessLevel AccessLevel, Core.AccessLevel UserAccessLevel, double MinimumResamplingInterval, bool IsHistorizing, NodeId DataType, ValueRank DefaultRank = Core.ValueRank.Scalar)
                : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
            {
                this.Value = null;
                this.DataType = DataType;
                this.ValueRank = (int)DefaultRank;

                this.AccessLevel = AccessLevel;
                this.UserAccessLevel = UserAccessLevel;
                this.MinimumResamplingInterval = MinimumResamplingInterval;
                this.IsHistorizing = IsHistorizing;
            }
        }

        public class NodeVariableType : Node
        {
            public object Value
            {
                get; protected set;
            }

            public NodeId DataType
            {
                get; protected set;
            }

            public bool IsAbstract
            {
                get; protected set;
            }

            public NodeVariableType(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool IsAbstract)
                : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
            {
                this.IsAbstract = IsAbstract;
            }
        }

        public class NodeReferenceType : Node
        {
            public bool IsAbstract
            {
                get; protected set;
            }

            public bool IsSymmetric
            {
                get; protected set;
            }

            public LocalizedText InverseName
            {
                get; protected set;
            }

            public NodeReferenceType(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool IsAbstract, bool IsSymmetric, LocalizedText InverseName)
                : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
            {
                this.IsAbstract = IsAbstract;
                this.IsSymmetric = IsSymmetric;
                this.InverseName = InverseName;
            }
        }

        public class NodeMethod : Node
        {
            public bool IsExecutable
            {
                get; protected set;
            }

            public bool IsUserExecutable
            {
                get; protected set;
            }

            public NodeMethod(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool IsExecutable, bool IsUserExecutable)
                : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
            {
                this.IsExecutable = IsExecutable;
                this.IsUserExecutable = IsUserExecutable;
            }
        }

        public class NodeView : Node
        {
            public bool ContainsNoLoops
            {
                get; protected set;
            }

            public byte EventNotifier
            {
                get; protected set;
            }

            public NodeView(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool ContainsNoLoops, byte EventNotifier)
                : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
            {
                this.ContainsNoLoops = ContainsNoLoops;
                this.EventNotifier = EventNotifier;
            }
        }

        public class NodeDataType : Node
        {
            public bool IsAbstract
            {
                get; protected set;
            }

            public NodeDataType(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool IsAbstract)
                : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
            {
                this.IsAbstract = IsAbstract;
            }
        }
    }
}
