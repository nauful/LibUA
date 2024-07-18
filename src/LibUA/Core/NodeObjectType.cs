using System;

namespace LibUA
{
    namespace Core
    {
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
    }
}
