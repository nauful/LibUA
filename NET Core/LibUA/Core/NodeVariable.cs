
// Type: LibUA.Core.NodeVariable



namespace LibUA.Core
{
    public class NodeVariable : Node
    {
        public object Value { get; set; }

        public NodeId DataType { get; protected set; }

        public AccessLevel AccessLevel { get; protected set; }

        public AccessLevel UserAccessLevel { get; protected set; }

        public double MinimumResamplingInterval { get; protected set; }

        public bool IsHistorizing { get; protected set; }

        public int ValueRank { get; protected set; }

        public NodeVariable(
          NodeId Id,
          QualifiedName BrowseName,
          LocalizedText DisplayName,
          LocalizedText Description,
          uint WriteMask,
          uint UserWriteMask,
          AccessLevel AccessLevel,
          AccessLevel UserAccessLevel,
          double MinimumResamplingInterval,
          bool IsHistorizing,
          NodeId DataType)
          : base(Id, NodeClass.ObjectType, BrowseName, DisplayName, Description, WriteMask, UserWriteMask)
        {
            this.Value = null;
            this.DataType = DataType;
            this.ValueRank = -1;
            this.AccessLevel = AccessLevel;
            this.UserAccessLevel = UserAccessLevel;
            this.MinimumResamplingInterval = MinimumResamplingInterval;
            this.IsHistorizing = IsHistorizing;
        }
    }
}
