
// Type: LibUA.Core.BrowsePath



namespace LibUA.Core
{
    public class BrowsePath
    {
        public NodeId StartingNode { get; protected set; }

        public RelativePathElement[] RelativePath { get; protected set; }

        public BrowsePath(NodeId StartingNode, RelativePathElement[] RelativePath)
        {
            this.StartingNode = StartingNode;
            this.RelativePath = RelativePath;
        }
    }
}
