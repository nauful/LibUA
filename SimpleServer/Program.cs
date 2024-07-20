using LibUA.Server;
using Microsoft.Extensions.Logging;

namespace SimpleServer
{
    internal class Program
    {
        static ILogger? logger;

        static void Main(string[] args)
        {
            var app = new SimpleServerApplication();

            using (ILoggerFactory factory = LoggerFactory.Create(builder => builder.AddConsole()))
            {
                logger = factory.CreateLogger(nameof(Main));
            }

            var server = new Master(app, 4840, 10, 30, 100, logger);

            server.Start();
            Console.ReadKey();
            server.Stop();
        }
    }
}
