
// Type: LibUA.Core.ReferenceNode



namespace LibUA.Core
{
    public class ReferenceNode
    {
        public NodeId ReferenceType { get; protected set; }

        public NodeId Target { get; protected set; }

        public bool IsInverse { get; protected set; }

        public override string ToString()
        {
            return string.Format("[{0}] {1} {2}", this.ReferenceType.ToString(), this.IsInverse ? "<-" : "->", this.Target.ToString());
        }

        public ReferenceNode(NodeId ReferenceType, NodeId Target, bool IsInverse)
        {
            this.ReferenceType = ReferenceType;
            this.Target = Target;
            this.IsInverse = IsInverse;
        }
    }
}
