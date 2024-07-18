using System;

namespace LibUA
{
    namespace Core
    {
        public class ReadAtTimeDetails
        {
            public DateTime[] ReqTimes { get; protected set; }
            public bool UseSimpleBounds { get; protected set; }

            public ReadAtTimeDetails(DateTime[] ReqTimes, bool UseSimpleBounds)
            {
                this.ReqTimes = ReqTimes;
                this.UseSimpleBounds = UseSimpleBounds;
            }
        }
    }
}
