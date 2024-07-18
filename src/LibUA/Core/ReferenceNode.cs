namespace LibUA
{
    namespace Core
    {
        public class ReferenceNode
        {
            public NodeId ReferenceType
            {
                get; protected set;
            }

            public NodeId Target
            {
                get; protected set;
            }

            public bool IsInverse
            {
                get; protected set;
            }

            public override string ToString()
            {
                return string.Format("[{0}] {1} {2}",
                    ReferenceType.ToString(),
                    IsInverse ? "<-" : "->",
                    Target.ToString());
            }

            public ReferenceNode(NodeId ReferenceType, NodeId Target, bool IsInverse)
            {
                this.ReferenceType = ReferenceType;
                this.Target = Target;
                this.IsInverse = IsInverse;
            }
        }
    }
}
