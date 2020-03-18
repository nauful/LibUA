using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibUA
{
	[Flags]
	public enum LogLevel
	{
		None = 0,
		Info = 1,
		Warn = 2,
		Error = 4,
	}

	public interface ILogger
	{
		bool HasLevel(LogLevel Level);
		void LevelSet(LogLevel Mask);

		void Log(LogLevel Level, string Str);
	}
}
