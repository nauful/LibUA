using LibUA.Core;

namespace LibUA.ValueTypes;

public static class EUInformationExtensions
{
    public static int CodingSize(this MemoryBuffer mem, EUInformation dv)
    {
        int sum = 0;

        sum += Coding.CodingSizeUAString(dv.NameSpaceUri);
        sum += Coding.CodingSize(dv.UnitId);
        sum += Coding.CodingSize(dv.DisplayName);
        sum += Coding.CodingSize(dv.Description);

        return sum;
    }

    public static bool Encode(this MemoryBuffer mem, EUInformation item)
    {
        if (!mem.EncodeUAString(item.NameSpaceUri)) { return false; }
        if (!mem.Encode(item.UnitId)) { return false; }
        if (!mem.Encode(item.DisplayName)) { return false; }
        if (!mem.Encode(item.Description)) { return false; }

        return true;
    }

    public static bool Decode(this MemoryBuffer mem, out EUInformation wv)
    {
        wv = null;

        if (!mem.DecodeUAString(out string namespaceUri)) { return false; }
        if (!mem.Decode(out int unitId)) { return false; }
        if (!mem.Decode(out LocalizedText displayName)) { return false; }
        if (!mem.Decode(out LocalizedText description)) { return false; }

        try
        {
            wv = new EUInformation()
            {
                NameSpaceUri = namespaceUri,
                UnitId = unitId,
                DisplayName = displayName,
                Description = description
            };
        }
        catch
        {
            return false;
        }

        return true;
    }
}
