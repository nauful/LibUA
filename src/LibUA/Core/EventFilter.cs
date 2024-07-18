namespace LibUA
{
    namespace Core
    {
        public class EventFilter : MonitoringFilter
        {
            public SimpleAttributeOperand[] SelectClauses { get; protected set; }
            public ContentFilterElement[] ContentFilters { get; protected set; }

            public EventFilter(SimpleAttributeOperand[] SelectClauses, ContentFilterElement[] ContentFilters)
            {
                this.SelectClauses = SelectClauses;
                this.ContentFilters = ContentFilters;
            }
        }
    }
}
