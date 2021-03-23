
// Type: LibUA.ILogger



namespace LibUA
{
    public interface ILogger
    {
        bool HasLevel(LogLevel Level);

        void LevelSet(LogLevel Mask);

        void Log(LogLevel Level, string Str);
    }
}
