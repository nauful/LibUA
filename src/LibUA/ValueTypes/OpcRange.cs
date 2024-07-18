using LibUA.Core;

namespace LibUA.ValueTypes;

public class OpcRange
{
    public double High { get; set; }
    public double Low { get; set; }
}

public static class RangeExtensions
{
    public static int CodingSize(this MemoryBuffer mem, OpcRange dv)
    {
        int sum = 0;

        sum += Coding.CodingSize(dv.Low);
        sum += Coding.CodingSize(dv.High);

        return sum;
    }

    public static bool Encode(this MemoryBuffer mem, OpcRange item)
    {
        if (!mem.Encode(item.Low)) { return false; }
        if (!mem.Encode(item.High)) { return false; }

        return true;
    }

    public static bool Decode(this MemoryBuffer mem, out OpcRange wv)
    {
        wv = null;

        if (!mem.Decode(out double low)) { return false; }
        if (!mem.Decode(out double high)) { return false; }

        try
        {
            wv = new OpcRange()
            {
                High = high,
                Low = low
            };
        }
        catch
        {
            return false;
        }

        return true;
    }
}
