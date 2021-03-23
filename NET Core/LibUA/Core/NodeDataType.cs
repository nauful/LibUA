
// Type: LibUA.Core.NodeDataType



namespace LibUA.Core
{
    public class NodeDataType : Node
    {
        public bool IsAbstract { get; protected set; }

        public NodeDataType(
          NodeId Id,
          QualifiedName BrowseName,
          LocalizedText DisplayName,
          LocalizedText Description,
          uint WriteMask,
          uint UserWriteMask,
          bool IsAbstract)
          : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
        {
            this.IsAbstract = IsAbstract;
        }
    }
}
