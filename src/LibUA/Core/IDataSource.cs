namespace LibUA
{
    namespace Core
    {
        public interface IDataSource
        {
            object GetValue(NodeId nodeId);
            void SetValue(NodeId nodeId, object newValue);
        }
    }
}
