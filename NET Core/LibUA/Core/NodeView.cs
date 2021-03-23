
// Type: LibUA.Core.NodeView



namespace LibUA.Core
{
    public class NodeView : Node
    {
        public bool ContainsNoLoops { get; protected set; }

        public byte EventNotifier { get; protected set; }

        public NodeView(
          NodeId Id,
          QualifiedName BrowseName,
          LocalizedText DisplayName,
          LocalizedText Description,
          uint WriteMask,
          uint UserWriteMask,
          bool ContainsNoLoops,
          byte EventNotifier)
          : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
        {
            this.ContainsNoLoops = ContainsNoLoops;
            this.EventNotifier = EventNotifier;
        }
    }
}
