using System;

namespace LibUA
{
    namespace Core
    {
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
    }
}
