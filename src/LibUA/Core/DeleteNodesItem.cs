using System;

namespace LibUA
{
    namespace Core
    {
        public class DeleteNodesItem
        {
            public NodeId NodeId { get; }
            public Boolean DeleteTargetReferences { get; }

            public DeleteNodesItem(NodeId nodeId, bool deleteTargetReferences)
            {
                NodeId = nodeId;
                DeleteTargetReferences = deleteTargetReferences;
            }
        }
    }
}
