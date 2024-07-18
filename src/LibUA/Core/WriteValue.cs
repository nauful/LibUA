namespace LibUA
{
    namespace Core
    {
        public class WriteValue
        {
            public NodeId NodeId { get; protected set; }
            public NodeAttribute AttributeId { get; protected set; }
            public string IndexRange { get; protected set; }
            public DataValue Value { get; protected set; }

            public WriteValue(NodeId NodeId, NodeAttribute AttributeId, string IndexRange, DataValue Value)
            {
                this.NodeId = NodeId;
                this.AttributeId = AttributeId;
                this.IndexRange = IndexRange;
                this.Value = Value;
            }
        }
    }
}
