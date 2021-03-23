
// Type: LibUA.Core.AddNodesResult



namespace LibUA.Core
{
    public class AddNodesResult
    {
        public StatusCode StatusCode { get; }

        public NodeId AddedNodeId { get; }

        public AddNodesResult(StatusCode statusCode, NodeId addedNodeId)
        {
            this.StatusCode = statusCode;
            this.AddedNodeId = addedNodeId;
        }
    }
}
