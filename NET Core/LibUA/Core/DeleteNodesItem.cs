
// Type: LibUA.Core.DeleteNodesItem



namespace LibUA.Core
{
    public class DeleteNodesItem
    {
        public NodeId NodeId { get; }

        public bool DeleteTargetReferences { get; }

        public DeleteNodesItem(NodeId nodeId, bool deleteTargetReferences)
        {
            this.NodeId = nodeId;
            this.DeleteTargetReferences = deleteTargetReferences;
        }
    }
}
