
// Type: LibUA.Core.CallMethodResult



namespace LibUA.Core
{
    public class CallMethodResult
    {
        public uint StatusCode { get; protected set; }

        public uint[] Results { get; protected set; }

        public object[] Outputs { get; protected set; }

        public CallMethodResult(uint StatusCode, uint[] Results, object[] Outputs)
        {
            this.StatusCode = StatusCode;
            this.Results = Results;
            this.Outputs = Outputs;
        }
    }
}
