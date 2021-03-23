
// Type: LibUA.Core.EventFilter



namespace LibUA.Core
{
    public class EventFilter
    {
        public SimpleAttributeOperand[] SelectClauses { get; protected set; }

        public ContentFilterElement[] ContentFilters { get; protected set; }

        public EventFilter(
          SimpleAttributeOperand[] SelectClauses,
          ContentFilterElement[] ContentFilters)
        {
            this.SelectClauses = SelectClauses;
            this.ContentFilters = ContentFilters;
        }
    }
}
