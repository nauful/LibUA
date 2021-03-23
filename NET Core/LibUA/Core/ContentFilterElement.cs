
// Type: LibUA.Core.ContentFilterElement



namespace LibUA.Core
{
    public class ContentFilterElement
    {
        public FilterOperator Operator { get; protected set; }

        public FilterOperand[] Operands { get; protected set; }

        public ContentFilterElement(FilterOperator Operator, FilterOperand[] Operands)
        {
            this.Operator = Operator;
            this.Operands = Operands;
        }
    }
}
