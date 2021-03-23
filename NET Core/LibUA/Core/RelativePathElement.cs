
// Type: LibUA.Core.RelativePathElement



namespace LibUA.Core
{
    public class RelativePathElement
    {
        public NodeId ReferenceTypeId { get; protected set; }

        public bool IsInverse { get; protected set; }

        public bool IncludeSubtypes { get; protected set; }

        public QualifiedName TargetName { get; protected set; }

        public RelativePathElement(
          NodeId ReferenceTypeId,
          bool IsInverse,
          bool IncludeSubtypes,
          QualifiedName TargetName)
        {
            this.ReferenceTypeId = ReferenceTypeId;
            this.IsInverse = IsInverse;
            this.IncludeSubtypes = IncludeSubtypes;
            this.TargetName = TargetName;
        }
    }
}
