
// Type: LibUA.Core.CallMethodRequest



namespace LibUA.Core
{
    public class CallMethodRequest
    {
        public NodeId ObjectId { get; protected set; }

        public NodeId MethodId { get; protected set; }

        public object[] InputArguments { get; protected set; }

        public CallMethodRequest(NodeId ObjectId, NodeId MethodId, object[] InputArguments)
        {
            this.ObjectId = ObjectId;
            this.MethodId = MethodId;
            this.InputArguments = InputArguments;
        }
    }
}
