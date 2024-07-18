using System;

namespace LibUA
{
    namespace Core
    {

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
