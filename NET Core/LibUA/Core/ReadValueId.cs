
// Type: LibUA.Core.ReadValueId



namespace LibUA.Core
{
    public class ReadValueId
    {
        public NodeId NodeId { get; protected set; }

        public NodeAttribute AttributeId { get; protected set; }

        public string IndexRange { get; protected set; }

        public QualifiedName DataEncoding { get; protected set; }

        public ReadValueId(NodeId NodeId, NodeAttribute AttributeId)
          : this(NodeId, AttributeId, null, new QualifiedName(0, null))
        {
        }

        public ReadValueId(
          NodeId NodeId,
          NodeAttribute AttributeId,
          string IndexRange,
          QualifiedName DataEncoding)
        {
            this.NodeId = NodeId;
            this.AttributeId = AttributeId;
            this.IndexRange = IndexRange;
            this.DataEncoding = DataEncoding;
        }
    }
}
