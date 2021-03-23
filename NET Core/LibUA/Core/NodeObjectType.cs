
// Type: LibUA.Core.NodeObjectType



namespace LibUA.Core
{
    public class NodeObjectType : Node
    {
        public bool IsAbstract { get; protected set; }

        public NodeObjectType(
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
