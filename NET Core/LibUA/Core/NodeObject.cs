
// Type: LibUA.Core.NodeObject



namespace LibUA.Core
{
    public class NodeObject : Node
    {
        public byte EventNotifier { get; protected set; }

        public NodeObject(
          NodeId Id,
          QualifiedName BrowseName,
          LocalizedText DisplayName,
          LocalizedText Description,
          uint WriteMask,
          uint UserWriteMask,
          byte EventNotifier)
          : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
        {
            this.EventNotifier = EventNotifier;
        }
    }
}
