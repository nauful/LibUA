
// Type: LibUA.Core.HistoryUpdateData



namespace LibUA.Core
{
    public class HistoryUpdateData
    {
        public PerformUpdateType PerformUpdate { get; protected set; }

        public NodeId NodeId { get; protected set; }

        public DataValue[] Value { get; protected set; }

        public HistoryUpdateData(NodeId NodeId, PerformUpdateType PerformUpdate, DataValue[] Value)
        {
            this.NodeId = NodeId;
            this.PerformUpdate = PerformUpdate;
            this.Value = Value;
        }
    }
}
