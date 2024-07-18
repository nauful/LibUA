namespace LibUA
{
    namespace Core
    {
        public class BrowsePath
        {
            public NodeId StartingNode
            {
                get; protected set;
            }

            public RelativePathElement[] RelativePath
            {
                get; protected set;
            }

            public BrowsePath(NodeId StartingNode, RelativePathElement[] RelativePath)
            {
                this.StartingNode = StartingNode;
                this.RelativePath = RelativePath;
            }
        }
    }
}
