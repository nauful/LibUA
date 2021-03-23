
// Type: LibUA.Core.DeleteReferencesItem



namespace LibUA.Core
{
    public class DeleteReferencesItem
    {
        public NodeId SourceNodeId { get; set; }

        public NodeId ReferenceTypeId { get; set; }

        public bool IsForward { get; set; }

        public NodeId TargetNodeId { get; set; }

        public bool DeleteBidirectional { get; set; }
    }
}
