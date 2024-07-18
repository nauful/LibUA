namespace LibUA
{
    namespace Core
    {
        public class DataChangeFilter : MonitoringFilter
        {
            public DataChangeTrigger Trigger { get; protected set; }
            public DeadbandType DeadbandType { get; protected set; }
            public double DeadbandValue { get; protected set; }

            public DataChangeFilter(DataChangeTrigger trigger, DeadbandType deadbandType, double deadbandValue)
            {
                this.Trigger = trigger;
                this.DeadbandType = deadbandType;
                this.DeadbandValue = deadbandValue;
            }
        }
    }
}
