namespace LibUA
{
    namespace Core
    {
        public class ReferenceDescription
        {
            public NodeId ReferenceTypeId
            {
                get; protected set;
            }

            public bool IsForward
            {
                get; protected set;
            }

            public NodeId TargetId
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

            public NodeClass NodeClass
            {
                get; protected set;
            }

            public NodeId TypeDefinition
            {
                get; protected set;
            }

            public ReferenceDescription(NodeId ReferenceTypeId, bool IsForward, NodeId TargetId, QualifiedName BrowseName, LocalizedText DisplayName, NodeClass NodeClass, NodeId TypeDefinition)
            {
                this.ReferenceTypeId = ReferenceTypeId;
                this.IsForward = IsForward;
                this.TargetId = TargetId;
                this.BrowseName = BrowseName;
                this.DisplayName = DisplayName;
                this.NodeClass = NodeClass;
                this.TypeDefinition = TypeDefinition;
            }
        }
    }
}
