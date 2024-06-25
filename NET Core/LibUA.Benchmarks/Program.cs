using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;

internal class Program
{
    private static void Main(string[] args)
    {
        var summary = BenchmarkRunner.Run(typeof(Program).Assembly);
    }
}
