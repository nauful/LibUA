using System;

namespace LibUA
{
    namespace Core
    {
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
    }
}
