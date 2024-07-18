using System;

namespace LibUA
{
    namespace Core
    {
        public class CallMethodResult
        {
            public UInt32 StatusCode { get; protected set; }
            public UInt32[] Results { get; protected set; }
            public object[] Outputs { get; protected set; }

            public CallMethodResult(UInt32 StatusCode, UInt32[] Results, object[] Outputs)
            {
                this.StatusCode = StatusCode;
                this.Results = Results;
                this.Outputs = Outputs;
            }
        }
    }
}
