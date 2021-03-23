
// Type: LibUA.Core.HistoryReadValueId



namespace LibUA.Core
{
    public class HistoryReadValueId
    {
        public NodeId NodeId { get; protected set; }

        public string IndexRange { get; protected set; }

        public QualifiedName DataEncoding { get; protected set; }

        public byte[] ContinuationPoint { get; protected set; }

        public HistoryReadValueId(
          NodeId NodeId,
          string IndexRange,
          QualifiedName DataEncoding,
          byte[] ContinuationPoint)
        {
            this.NodeId = NodeId;
            this.IndexRange = IndexRange;
            this.DataEncoding = DataEncoding;
            this.ContinuationPoint = ContinuationPoint;
        }
    }
}
