using System;

namespace LibUA
{
    namespace Core
    {
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
    }
}
