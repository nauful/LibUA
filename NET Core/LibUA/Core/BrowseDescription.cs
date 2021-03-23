
// Type: LibUA.Core.BrowseDescription



namespace LibUA.Core
{
    public class BrowseDescription
    {
        public NodeId Id { get; protected set; }

        public BrowseDirection Direction { get; protected set; }

        public NodeId ReferenceType { get; protected set; }

        public bool IncludeSubtypes { get; protected set; }

        public uint NodeClassMask { get; protected set; }

        public BrowseResultMask ResultMask { get; protected set; }

        public BrowseDescription(
          NodeId Id,
          BrowseDirection Direction,
          NodeId ReferenceType,
          bool IncludeSubtypes,
          uint NodeClassMask,
          BrowseResultMask ResultMask)
        {
            this.Id = Id;
            this.Direction = Direction;
            this.ReferenceType = ReferenceType;
            this.IncludeSubtypes = IncludeSubtypes;
            this.NodeClassMask = NodeClassMask;
            this.ResultMask = ResultMask;
        }
    }
}
