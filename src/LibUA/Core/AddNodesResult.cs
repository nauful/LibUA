namespace LibUA
{
    namespace Core
    {
        public class AddNodesResult
        {
            public StatusCode StatusCode { get; }

            public NodeId AddedNodeId { get; }

            public AddNodesResult(StatusCode statusCode, NodeId addedNodeId)
            {
                StatusCode = statusCode;
                AddedNodeId = addedNodeId;
            }
        }
    }
}
