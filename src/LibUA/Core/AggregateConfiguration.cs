namespace LibUA
{
    namespace Core
    {
        public class AggregateConfiguration
        {
            public bool UseServerCapabilitiesDefaults { get; protected set; }
            public bool TreatUncertainAsBad { get; protected set; }
            public double PercentDataBad { get; protected set; }
            public double PercentDataGood { get; protected set; }
            public bool UseSlopedExtrapolation { get; protected set; }

            public AggregateConfiguration(bool UseServerCapabilitiesDefaults, bool TreatUncertainAsBad, double PercentDataBad, double PercentDataGood, bool UseSlopedExtrapolation)
            {
                this.UseServerCapabilitiesDefaults = UseServerCapabilitiesDefaults;
                this.TreatUncertainAsBad = TreatUncertainAsBad;
                this.PercentDataBad = PercentDataBad;
                this.PercentDataGood = PercentDataGood;
                this.UseSlopedExtrapolation = UseSlopedExtrapolation;
            }
        }
    }
}
