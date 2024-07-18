namespace LibUA
{
    namespace Core
    {
        public class AddNodesItem
        {
            public NodeId ParentNodeId { get; set; }
            public NodeId ReferenceTypeId { get; set; }
            public NodeId RequestedNewNodeId { get; set; }
            public QualifiedName BrowseName { get; set; }
            public NodeClass NodeClass { get; set; }
            public ExtensionObject NodeAttributes { get; set; }
            public NodeId TypeDefinition { get; set; }
        }
    }
}
