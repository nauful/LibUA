using LibUA.ValueTypes;
using System;
using System.Collections.Concurrent;

namespace LibUA
{
    namespace Core
    {
        public class ExtensionObject
        {
            private static ConcurrentDictionary<Type, Func<MemoryBuffer, NodeId>> _objectEncoders = new();
            private static ConcurrentDictionary<NodeId, Func<MemoryBuffer, object>> _objectDecoders = new();
            public static void RegisterEncoder<TObject>(Func<MemoryBuffer, NodeId> encoder)
            {
                _objectEncoders[typeof(TObject)] = encoder;
            }

            public static void RegisterDecoder<TObject>(NodeId TypeId, Func<MemoryBuffer, TObject> decoder) where TObject : class
            {
                _objectDecoders[TypeId] = decoder;
            }

            public NodeId TypeId { get; set; }
            public byte[] Body { get; set; }

            public object Payload { get; set; }

            public bool TryEncodeByteString(int BufferCapacity)
            {
                TypeId = null;
                if (Payload != null)
                {
                    using var buffer = new MemoryBuffer(BufferCapacity);
                    UAConst payloadType = 0;

                    if (_objectEncoders.TryGetValue(Payload.GetType(), out var encoder))
                    {
                        TypeId = encoder(buffer);
                        if (TypeId == null)
                        {
                            return false;
                        }
                    }
                    else
                    {
                        switch (Payload)
                        {
                            case ObjectAttributes oa:
                                payloadType = UAConst.ObjectAttributes_Encoding_DefaultBinary;
                                if (!buffer.Encode(oa)) { return false; }
                                break;
                            case ObjectTypeAttributes ota:
                                payloadType = UAConst.ObjectTypeAttributes_Encoding_DefaultBinary;
                                if (!buffer.Encode(ota)) { return false; }
                                break;
                            case VariableAttributes va:
                                payloadType = UAConst.VariableAttributes_Encoding_DefaultBinary;
                                if (!buffer.Encode(va)) { return false; }
                                break;
                            case VariableTypeAttributes vta:
                                payloadType = UAConst.VariableTypeAttributes_Encoding_DefaultBinary;
                                if (!buffer.Encode(vta)) { return false; }
                                break;
                            case Argument arg:
                                payloadType = UAConst.Argument_Encoding_DefaultBinary;
                                if (!buffer.Encode(arg)) { return false; }
                                break;
                            case EUInformation eui:
                                payloadType = UAConst.EUInformation;
                                if (!buffer.Encode(eui)) { return false; }
                                break;
                            case OpcRange range:
                                payloadType = UAConst.Range;
                                if (!buffer.Encode(range)) { return false; }
                                break;
                            default:
                                break;
                        }

                        if (payloadType != 0)
                        {
                            TypeId = new NodeId(payloadType);
                        }
                    }

                    if (TypeId != null)
                    {
                        Body = new byte[buffer.Position];
                        Array.Copy(buffer.Buffer, Body, Body.Length);
                        return true;
                    }

                    return false;
                }

                return false;
            }

            public bool TryDecodeByteString()
            {
                var tmp = new MemoryBuffer(Body);

                if (_objectDecoders.TryGetValue(TypeId, out var decoder))
                {
                    Payload = decoder(tmp);
                    if (Payload != null)
                    {
                        return true;
                    }
                }

                switch (TypeId.NumericIdentifier)
                {
                    case (uint)UAConst.ObjectAttributes_Encoding_DefaultBinary:
                        ObjectAttributes oa;
                        if (!tmp.Decode(out oa)) { return false; }
                        Payload = oa;
                        break;
                    case (uint)UAConst.ObjectTypeAttributes_Encoding_DefaultBinary:
                        ObjectTypeAttributes ota;
                        if (!tmp.Decode(out ota)) { return false; }
                        Payload = ota;
                        break;
                    case (uint)UAConst.VariableAttributes_Encoding_DefaultBinary:
                        VariableAttributes va;
                        if (!tmp.Decode(out va)) { return false; }
                        Payload = va;
                        break;
                    case (uint)UAConst.VariableTypeAttributes_Encoding_DefaultBinary:
                        VariableTypeAttributes vta;
                        if (!tmp.Decode(out vta)) { return false; }
                        Payload = vta;
                        break;
                    case (uint)UAConst.Argument_Encoding_DefaultBinary:
                        Argument arg;
                        if (!tmp.Decode(out arg)) { return false; }
                        Payload = arg;
                        break;
                    case (uint)UAConst.EUInformation:
                        EUInformation eui;
                        if (!tmp.Decode(out eui)) { return false; }
                        Payload = eui;
                        break;
                    case (uint)UAConst.Range:
                        OpcRange range;
                        if (!tmp.Decode(out range)) { return false; }
                        Payload = range;
                        break;
                    default:
                        break;
                }

                return Payload != null;
            }
        }
    }
}
