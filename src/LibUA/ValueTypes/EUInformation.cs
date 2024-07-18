using LibUA.Core;
using System;

namespace LibUA.ValueTypes;

public class EUInformation
{
    public string NameSpaceUri { get; set; } = "http://www.opcfoundation.org/UA/units/un/cefact";
    public int UnitId { get; set; } = -1;
    public LocalizedText DisplayName { get; set; } = new("");
    public LocalizedText Description { get; set; } = new("");
}
