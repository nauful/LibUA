
// Type: LibUA.Core.AddReferencesItem



namespace LibUA.Core
{
    public class AddReferencesItem
    {
        public NodeId SourceNodeId { get; set; }

        public NodeId ReferenceTypeId { get; set; }

        public bool IsForward { get; set; }

        public string TargetServerUri { get; set; }

        public NodeId TargetNodeId { get; set; }

        public NodeClass TargetNodeClass { get; set; }
    }
}
