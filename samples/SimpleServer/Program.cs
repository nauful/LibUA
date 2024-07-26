using LibUA.Server;
using Microsoft.Extensions.Logging;

namespace SimpleServer
{
    internal class Program
    {
        static ILoggerFactory loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());

        static void Main(string[] args)
        {
            var app = new SimpleServerApplication();
            var server = new Master(app, 4840, 10, 30, 100, loggerFactory.CreateLogger<Master>());

            server.Start();
            Console.ReadKey();
            server.Stop();
        }
    }
}
