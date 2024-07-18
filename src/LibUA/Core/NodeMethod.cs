using System;

namespace LibUA
{
    namespace Core
    {
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
    }
}
