using System;
using System.Collections.Generic;

namespace LibUA
{
    namespace Core
    {
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
    }
}
