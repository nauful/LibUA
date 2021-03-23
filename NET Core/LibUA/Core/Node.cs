
// Type: LibUA.Core.Node



using System.Collections.Generic;

namespace LibUA.Core
{
    public class Node
    {
        public List<ReferenceNode> References { get; protected set; }

        public NodeId Id { get; protected set; }

        public NodeClass Class { get; protected set; }

        public QualifiedName BrowseName { get; protected set; }

        public LocalizedText DisplayName { get; protected set; }

        public LocalizedText Description { get; protected set; }

        public uint WriteMask { get; protected set; }

        public uint UserWriteMask { get; protected set; }

        public Node(
          NodeId Id,
          NodeClass Class,
          QualifiedName BrowseName,
          LocalizedText DisplayName,
          LocalizedText Description,
          uint WriteMask,
          uint UserWriteMask)
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
            switch (this)
            {
                case NodeObject _:
                    nodeClass = NodeClass.Object;
                    break;
                case NodeVariable _:
                    nodeClass = NodeClass.Variable;
                    break;
                case NodeMethod _:
                    nodeClass = NodeClass.Method;
                    break;
                case NodeObjectType _:
                    nodeClass = NodeClass.ObjectType;
                    break;
                case NodeVariableType _:
                    nodeClass = NodeClass.VariableType;
                    break;
                case NodeReferenceType _:
                    nodeClass = NodeClass.ReferenceType;
                    break;
                case NodeDataType _:
                    nodeClass = NodeClass.DataType;
                    break;
                case NodeView _:
                    nodeClass = NodeClass.View;
                    break;
            }
            return nodeClass;
        }
    }
}
