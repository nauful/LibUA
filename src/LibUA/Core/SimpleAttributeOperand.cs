namespace LibUA
{
    namespace Core
    {
        public class SimpleAttributeOperand : FilterOperand
        {
            public NodeId TypeDefinitionId
            {
                get; protected set;
            }

            public QualifiedName[] BrowsePath
            {
                get; protected set;
            }

            public NodeAttribute AttributeId
            {
                get; protected set;
            }

            public string IndexRange
            {
                get; protected set;
            }

            public SimpleAttributeOperand(NodeId TypeDefinitionId, QualifiedName[] BrowsePath, NodeAttribute AttributeId, string IndexRange)
            {
                this.TypeDefinitionId = TypeDefinitionId;
                this.BrowsePath = BrowsePath;
                this.AttributeId = AttributeId;
                this.IndexRange = IndexRange;
            }

            public SimpleAttributeOperand(QualifiedName[] BrowsePath)
            {
                this.BrowsePath = BrowsePath;
            }
        }
    }
}
