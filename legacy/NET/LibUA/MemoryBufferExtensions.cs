using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LibUA.Core;

namespace LibUA
{
    public static class MemoryBufferExtensions
    {
        private static byte DoubleToByte(double v)
        {
            int i = (int)(v / 1.0);
            if (i <= 0) { return 0; }
            if (i >= 255) { return 255; }

            return (byte)i;
        }

        private static double ByteToDouble(byte b)
        {
            return b / 255.0;
        }

        public static bool Encode(this MemoryBuffer mem, AggregateConfiguration ac)
        {
            if (!mem.Encode(ac.UseServerCapabilitiesDefaults)) { return false; }
            if (!mem.Encode(ac.TreatUncertainAsBad)) { return false; }
            if (!mem.Encode(DoubleToByte(ac.PercentDataBad))) { return false; }
            if (!mem.Encode(DoubleToByte(ac.PercentDataGood))) { return false; }
            if (!mem.Encode(ac.UseSlopedExtrapolation)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out AggregateConfiguration ac)
        {
            ac = null;


            if (!mem.Decode(out bool UseServerCapabilitiesDefaults)) { return false; }
            if (!mem.Decode(out bool TreatUncertainAsBad)) { return false; }
            if (!mem.Decode(out byte PercentDataBad)) { return false; }
            if (!mem.Decode(out byte PercentDataGood)) { return false; }
            if (!mem.Decode(out bool UseSlopedExtrapolation)) { return false; }

            try
            {
                ac = new AggregateConfiguration(UseServerCapabilitiesDefaults, TreatUncertainAsBad, ByteToDouble(PercentDataBad), ByteToDouble(PercentDataGood), UseSlopedExtrapolation);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, WriteValue wv)
        {
            if (!mem.Encode(wv.NodeId)) { return false; }
            if (!mem.Encode((UInt32)wv.AttributeId)) { return false; }
            if (!mem.EncodeUAString(wv.IndexRange)) { return false; }
            if (!mem.Encode(wv.Value)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out WriteValue wv)
        {
            wv = null;


            if (!mem.Decode(out NodeId nodeId)) { return false; }
            if (!mem.Decode(out uint attributeIdUint)) { return false; }
            if (!mem.DecodeUAString(out string indexRange)) { return false; }
            if (!mem.Decode(out DataValue value)) { return false; }

            try
            {
                wv = new WriteValue(nodeId, (NodeAttribute)attributeIdUint, indexRange, value);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoredItemModifyRequest rq)
        {
            if (!mem.Encode(rq.MonitoredItemId)) { return false; }
            if (!mem.Encode(rq.Parameters)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoredItemModifyRequest rq)
        {
            rq = null;


            if (!mem.Decode(out uint MonitoredItemId)) { return false; }
            if (!mem.Decode(out MonitoringParameters Parameters)) { return false; }

            try
            {
                rq = new MonitoredItemModifyRequest(MonitoredItemId, Parameters);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out BrowsePathResult bp)
        {
            bp = null;

            BrowsePathTarget[] Targets;

            if (!mem.Decode(out uint StatusCodeUint)) { return false; }
            if (!mem.DecodeArraySize(out uint NumTargets)) { return false; }
            Targets = new BrowsePathTarget[NumTargets];
            for (uint i = 0; i < NumTargets; i++)
            {
                if (!mem.Decode(out Targets[i].Target)) { return false; }
                if (!mem.Decode(out Targets[i].RemainingPathIndex)) { return false; }
            }

            try
            {
                bp = new BrowsePathResult((StatusCode)StatusCodeUint, Targets);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, BrowsePathResult bp)
        {
            if (!mem.Encode((UInt32)bp.StatusCode)) { return false; }
            if (bp.Targets == null)
            {
                return mem.Encode((UInt32)0xFFFFFFFFu);
            }

            if (!mem.Encode((UInt32)bp.Targets.Length)) { return false; }
            for (int i = 0; i < bp.Targets.Length; i++)
            {
                if (!mem.Encode(bp.Targets[i].Target)) { return false; }
                if (!mem.Encode(bp.Targets[i].RemainingPathIndex)) { return false; }
            }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out RelativePathElement rp)
        {
            rp = null;


            if (!mem.Decode(out NodeId ReferenceTypeId)) { return false; }
            if (!mem.Decode(out bool IsInverse)) { return false; }
            if (!mem.Decode(out bool IncludeSubtypes)) { return false; }
            if (!mem.Decode(out QualifiedName TargetName)) { return false; }

            try
            {
                rp = new RelativePathElement(ReferenceTypeId, IsInverse, IncludeSubtypes, TargetName);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, RelativePathElement rp)
        {
            if (!mem.Encode(rp.ReferenceTypeId)) { return false; }
            if (!mem.Encode(rp.IsInverse)) { return false; }
            if (!mem.Encode(rp.IncludeSubtypes)) { return false; }
            if (!mem.Encode(rp.TargetName)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out BrowsePath bp)
        {
            bp = null;

            RelativePathElement[] RelativePath;

            if (!mem.Decode(out NodeId StartingNode)) { return false; }
            if (!mem.DecodeArraySize(out uint NumRelativePath)) { return false; }
            RelativePath = new RelativePathElement[NumRelativePath];
            for (uint i = 0; i < NumRelativePath; i++)
            {
                if (!mem.Decode(out RelativePath[i])) { return false; }
            }

            try
            {
                bp = new BrowsePath(StartingNode, RelativePath);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, BrowsePath bp)
        {
            if (!mem.Encode(bp.StartingNode)) { return false; }

            if (!mem.Encode((UInt32)bp.RelativePath.Length)) { return false; }
            for (int i = 0; i < bp.RelativePath.Length; i++)
            {
                if (!mem.Encode(bp.RelativePath[i])) { return false; }
            }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoredItemModifyResult mr)
        {
            mr = null;


            if (!mem.Decode(out uint StatusCodeUint)) { return false; }
            if (!mem.Decode(out double RevisedSamplingInterval)) { return false; }
            if (!mem.Decode(out uint RevisedQueueSize)) { return false; }
            if (!mem.Decode(out ExtensionObject Filter)) { return false; }

            try
            {
                mr = new MonitoredItemModifyResult((StatusCode)StatusCodeUint, RevisedSamplingInterval, RevisedQueueSize, Filter);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoredItemModifyResult mr)
        {
            if (!mem.Encode((UInt32)mr.StatusCode)) { return false; }
            if (!mem.Encode(mr.RevisedSamplingInterval)) { return false; }
            if (!mem.Encode(mr.RevisedQueueSize)) { return false; }
            if (!mem.Encode(mr.Filter)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoredItemCreateResult cr)
        {
            cr = null;


            if (!mem.Decode(out uint StatusCodeUint)) { return false; }
            if (!mem.Decode(out uint MonitoredItemId)) { return false; }
            if (!mem.Decode(out double RevisedSamplingInterval)) { return false; }
            if (!mem.Decode(out uint RevisedQueueSize)) { return false; }
            if (!mem.Decode(out ExtensionObject Filter)) { return false; }

            try
            {
                cr = new MonitoredItemCreateResult((StatusCode)StatusCodeUint, MonitoredItemId, RevisedSamplingInterval, RevisedQueueSize, Filter);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoredItemCreateResult cr)
        {
            if (!mem.Encode((UInt32)cr.StatusCode)) { return false; }
            if (!mem.Encode(cr.MonitoredItemId)) { return false; }
            if (!mem.Encode(cr.RevisedSamplingInterval)) { return false; }
            if (!mem.Encode(cr.RevisedQueueSize)) { return false; }
            if (!mem.Encode(cr.Filter)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out ContentFilterElement cfe)
        {
            cfe = null;

            if (!mem.Decode(out uint filterOperatorUint)) { return false; }
            if (!mem.DecodeArraySize(out uint numFilterOperands)) { return false; }

            var operands = new FilterOperand[numFilterOperands];
            for (uint i = 0; i < numFilterOperands; i++)
            {
                if (!mem.Decode(out NodeId _)) { return false; }

                if (!mem.Decode(out byte _)) { return false; }

                if (!mem.Decode(out uint _)) { return false; }

                // TODO: Always literal operand?
                if (!mem.VariantDecode(out object value)) { return false; }
                operands[i] = new LiteralOperand(value);
            }

            try
            {
                cfe = new ContentFilterElement((FilterOperator)filterOperatorUint, operands);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ContentFilterElement cfe)
        {
            if (!mem.Encode((UInt32)cfe.Operator)) { return false; }
            if (!mem.Encode((UInt32)cfe.Operands.Length)) { return false; }

            for (int i = 0; i < cfe.Operands.Length; i++)
            {
                NodeId typeId = new NodeId(597);
                byte encodingMask = 1;
                UInt32 eoSize = (UInt32)Coding.VariantCodingSize((cfe.Operands[i] as LiteralOperand).Value);

                if (!mem.Encode(typeId)) { return false; }
                if (!mem.Encode(encodingMask)) { return false; }
                if (!mem.Encode(eoSize)) { return false; }

                if (!mem.VariantEncode((cfe.Operands[i] as LiteralOperand).Value)) { return false; }
            }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoringFilter filter)
        {
            filter = null;


            if (!mem.Decode(out NodeId filterTypeId)) { return false; }
            if (!mem.Decode(out byte filterMask)) { return false; }

            if (filterTypeId.EqualsNumeric(0, 0) && filterMask == 0)
            {
                // No filter
                return true;
            }
            // Has binary body
            if (filterMask != 1) { return false; }

            if (!mem.Decode(out uint _)) { return false; }

            if (filterTypeId.EqualsNumeric(0, (uint)UAConst.EventFilter_Encoding_DefaultBinary) &&
                mem.Decode(out EventFilter eventFilter, false))
            {
                filter = eventFilter;
                return true;
            }
            else if (filterTypeId.EqualsNumeric(0, (uint)UAConst.DataChangeFilter_Encoding_DefaultBinary) &&
                mem.Decode(out DataChangeFilter dataChangeFilter, false))
            {
                filter = dataChangeFilter;
                return true;
            }

            return false;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoringFilter filter, bool includeType)
        {
            if (filter is EventFilter eventFiler)
            {
                return mem.Encode(eventFiler, includeType);
            }
            else if (filter is DataChangeFilter dataChangeFilter)
            {
                return mem.Encode(dataChangeFilter, includeType);
            }

            return false;
        }

        public static bool Decode(this MemoryBuffer mem, out EventFilter filter, bool includeType)
        {
            filter = null;

            if (includeType)
            {

                if (!mem.Decode(out NodeId filterTypeId)) { return false; }
                if (!mem.Decode(out byte filterMask)) { return false; }

                if (filterTypeId.EqualsNumeric(0, 0) && filterMask == 0)
                {
                    // No filter
                    return true;
                }

                if (!filterTypeId.EqualsNumeric(0, (uint)UAConst.EventFilter_Encoding_DefaultBinary)) { return false; }
                // Has binary body
                if (filterMask != 1) { return false; }

                if (!mem.Decode(out uint _)) { return false; }
            }

            if (!mem.DecodeArraySize(out uint numSelectClauses)) { return false; }

            SimpleAttributeOperand[] selectClauses = null;
            if (numSelectClauses != UInt32.MaxValue)
            {
                selectClauses = new SimpleAttributeOperand[numSelectClauses];
                for (uint i = 0; i < numSelectClauses; i++)
                {
                    QualifiedName[] browsePath;

                    if (!mem.Decode(out NodeId typeDefId)) { return false; }
                    if (!mem.DecodeArraySize(out uint numBrowsePath)) { return false; }
                    browsePath = new QualifiedName[numBrowsePath];
                    for (uint j = 0; j < numBrowsePath; j++)
                    {
                        if (!mem.Decode(out browsePath[j])) { return false; }
                    }

                    if (!mem.Decode(out uint attributeIdUint)) { return false; }
                    if (!mem.DecodeUAString(out string indexRange)) { return false; }

                    try
                    {
                        selectClauses[i] = new SimpleAttributeOperand(typeDefId, browsePath, (NodeAttribute)attributeIdUint, indexRange);
                    }
                    catch
                    {
                        return false;
                    }
                }
            }

            if (!mem.DecodeArraySize(out uint numContentFilters)) { return false; }

            ContentFilterElement[] contentFilters = null;
            if (numContentFilters != UInt32.MaxValue)
            {
                contentFilters = new ContentFilterElement[numContentFilters];
                for (uint i = 0; i < numContentFilters; i++)
                {
                    if (!mem.Decode(out contentFilters[i])) { return false; }
                }
            }

            try
            {
                filter = new EventFilter(selectClauses, contentFilters);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, EventFilter filter, bool includeType)
        {
            if (filter == null)
            {
                if (includeType)
                {
                    if (!mem.Encode(NodeId.Zero)) { return false; }
                    if (!mem.Encode((byte)0)) { return false; }
                }
                return true;
            }

            if (includeType)
            {
                // Default binary
                if (!mem.Encode(new NodeId(727))) { return false; }
                // Has binary body
                if (!mem.Encode((byte)1)) { return false; }
            }

            UInt32 eoFilterSize = 0;
            int eoFilterPos = mem.Position;
            if (includeType)
            {
                if (!mem.Encode(eoFilterSize)) { return false; }
            }

            if (filter.SelectClauses == null)
            {
                if (!mem.Encode((UInt32)0xFFFFFFFFu)) { return false; }
            }
            else
            {
                if (!mem.Encode((UInt32)filter.SelectClauses.Length)) { return false; }
                for (int i = 0; i < filter.SelectClauses.Length; i++)
                {
                    if (!mem.Encode(filter.SelectClauses[i].TypeDefinitionId)) { return false; }

                    if (!mem.Encode((UInt32)filter.SelectClauses[i].BrowsePath.Length)) { return false; }
                    for (int j = 0; j < filter.SelectClauses[i].BrowsePath.Length; j++)
                    {
                        if (!mem.Encode(filter.SelectClauses[i].BrowsePath[j])) { return false; }
                    }

                    if (!mem.Encode((UInt32)filter.SelectClauses[i].AttributeId)) { return false; }
                    if (!mem.EncodeUAString(filter.SelectClauses[i].IndexRange)) { return false; }
                }
            }

            if (filter.ContentFilters == null)
            {
                if (!mem.Encode((UInt32)0xFFFFFFFFu)) { return false; }
            }
            else
            {
                if (!mem.Encode((UInt32)filter.ContentFilters.Length)) { return false; }
                for (int i = 0; i < filter.ContentFilters.Length; i++)
                {
                    if (!mem.Encode(filter.ContentFilters[i])) { return false; }
                }
            }

            if (includeType)
            {
                var posRestore = mem.Position;
                mem.Position = eoFilterPos;
                if (!mem.Encode(eoFilterSize))
                {
                    mem.Position = posRestore;
                    return false;
                }
                mem.Position = posRestore;
            }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out DataChangeFilter filter, bool includeType)
        {
            filter = null;

            if (includeType)
            {

                if (!mem.Decode(out NodeId filterTypeId)) { return false; }
                if (!mem.Decode(out byte filterMask)) { return false; }

                if (filterTypeId.EqualsNumeric(0, 0) && filterMask == 0)
                {
                    // No filter
                    return true;
                }

                if (!filterTypeId.EqualsNumeric(0, (uint)UAConst.DataChangeFilter_Encoding_DefaultBinary)) { return false; }
                // Has binary body
                if (filterMask != 1) { return false; }

                if (!mem.Decode(out uint _)) { return false; }
            }

            if (!mem.Decode(out uint trigger)) { return false; }
            if (!mem.Decode(out uint deadbandType)) { return false; }

            if (!mem.Decode(out double deadbandValue)) { return false; }

            try
            {
                filter = new DataChangeFilter((DataChangeTrigger)trigger, (DeadbandType)deadbandType, deadbandValue);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, DataChangeFilter filter, bool includeType)
        {
            if (filter == null)
            {
                if (includeType)
                {
                    if (!mem.Encode(NodeId.Zero)) { return false; }
                    if (!mem.Encode((byte)0)) { return false; }
                }
                return true;
            }

            if (includeType)
            {
                // Default binary
                if (!mem.Encode(new NodeId(724))) { return false; }
                // Has binary body
                if (!mem.Encode((byte)1)) { return false; }
            }

            if (!mem.Encode((UInt32)filter.Trigger)) { return false; }
            if (!mem.Encode((UInt32)filter.DeadbandType)) { return false; }
            if (!mem.Encode(filter.DeadbandValue)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoringParameters para)
        {
            para = null;


            if (!mem.Decode(out uint ClientHandle)) { return false; }
            if (!mem.Decode(out double SamplingInterval)) { return false; }

            if (!mem.Decode(out MonitoringFilter Filter)) { return false; }

            if (!mem.Decode(out uint QueueSize)) { return false; }
            if (!mem.Decode(out bool DiscardOldest)) { return false; }

            try
            {
                para = new MonitoringParameters(ClientHandle, SamplingInterval, Filter, QueueSize, DiscardOldest);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoringParameters para)
        {
            if (!mem.Encode(para.ClientHandle)) { return false; }
            if (!mem.Encode(para.SamplingInterval)) { return false; }

            if (!mem.Encode(para.Filter, true)) { return false; }

            if (!mem.Encode(para.QueueSize)) { return false; }
            if (!mem.Encode(para.DiscardOldest)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out MonitoredItemCreateRequest cr)
        {
            cr = null;


            if (!mem.Decode(out ReadValueId itemToMonitor)) { return false; }
            if (!mem.Decode(out uint monitoringModeUint)) { return false; }
            if (!mem.Decode(out MonitoringParameters reqParameters)) { return false; }

            try
            {
                cr = new MonitoredItemCreateRequest(itemToMonitor, (MonitoringMode)monitoringModeUint, reqParameters);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, MonitoredItemCreateRequest cr)
        {
            if (!mem.Encode(cr.ItemToMonitor)) { return false; }
            if (!mem.Encode((UInt32)cr.Mode)) { return false; }
            if (!mem.Encode(cr.RequestedParameters)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out ReferenceDescription rd)
        {
            rd = null;


            if (!mem.Decode(out NodeId refTypeId)) { return false; }
            if (!mem.Decode(out bool isForward)) { return false; }
            if (!mem.Decode(out NodeId targetId)) { return false; }
            if (!mem.Decode(out QualifiedName browseName)) { return false; }
            if (!mem.Decode(out LocalizedText displayName)) { return false; }
            if (!mem.Decode(out int nodeClass)) { return false; }
            if (!mem.Decode(out NodeId typeDefId)) { return false; }

            try
            {
                rd = new ReferenceDescription(refTypeId, isForward, targetId, browseName, displayName, (NodeClass)nodeClass, typeDefId);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ReferenceDescription rd)
        {
            if (!mem.Encode(rd.ReferenceTypeId)) { return false; }
            if (!mem.Encode(rd.IsForward)) { return false; }
            if (!mem.Encode(rd.TargetId)) { return false; }
            if (!mem.Encode(rd.BrowseName)) { return false; }
            if (!mem.Encode(rd.DisplayName)) { return false; }
            if (!mem.Encode((Int32)rd.NodeClass)) { return false; }
            if (!mem.Encode(rd.TypeDefinition)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out BrowseDescription bd)
        {
            bd = null;


            if (!mem.Decode(out NodeId nodeId)) { return false; }
            if (!mem.Decode(out uint browseDir)) { return false; }
            if (!mem.Decode(out NodeId refTypeId)) { return false; }
            if (!mem.Decode(out bool includeSubtypes)) { return false; }
            if (!mem.Decode(out uint nodeClassMask)) { return false; }
            if (!mem.Decode(out uint resultMask)) { return false; }

            try
            {
                bd = new BrowseDescription(nodeId, (BrowseDirection)browseDir, refTypeId, includeSubtypes, nodeClassMask, (BrowseResultMask)resultMask);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, BrowseDescription bd)
        {
            if (!mem.Encode(bd.Id)) { return false; }
            if (!mem.Encode((UInt32)bd.Direction)) { return false; }
            if (!mem.Encode(bd.ReferenceType)) { return false; }
            if (!mem.Encode(bd.IncludeSubtypes)) { return false; }
            if (!mem.Encode((UInt32)bd.NodeClassMask)) { return false; }
            if (!mem.Encode((UInt32)bd.ResultMask)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out DataValue dv)
        {
            dv = null;

            object Value = null;
            uint statusCode = 0;
            Int64 sourceTimestamp = 0;
            Int64 serverTimestamp = 0;
            bool hasStatusCode = false, hasSourceTimestamp = false, hasServerTimestamp = false;

            if (!mem.Decode(out byte mask)) { return false; }

            if ((mask & 1) != 0)
            {
                if (!mem.VariantDecode(out Value)) { return false; }
            }

            if ((mask & 2) != 0)
            {
                if (!mem.Decode(out statusCode)) { return false; }
                hasStatusCode = true;
            }

            if ((mask & 4) != 0)
            {
                if (!mem.Decode(out sourceTimestamp)) { return false; }
                hasSourceTimestamp = true;
            }

            if ((mask & 8) != 0)
            {
                if (!mem.Decode(out serverTimestamp)) { return false; }
                hasServerTimestamp = true;
            }

            try
            {
                dv = new DataValue(Value,
                    hasStatusCode ? (StatusCode?)statusCode : null,
                    hasSourceTimestamp ? (DateTime?)DateTime.FromFileTimeUtc(sourceTimestamp) : null,
                    hasServerTimestamp ? (DateTime?)DateTime.FromFileTimeUtc(serverTimestamp) : null);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static int CodingSize(this MemoryBuffer mem, DataValue dv)
        {
            int sum = 0;

            sum += Coding.CodingSize(dv.GetEncodingMask());
            if (dv.Value != null)
            {
                sum += Coding.VariantCodingSize(dv.Value);
            }

            if (dv.StatusCode.HasValue)
            {
                sum += Coding.CodingSize((UInt32)dv.StatusCode.Value);
            }

            if (dv.SourceTimestamp.HasValue)
            {
                sum += Coding.CodingSize(dv.SourceTimestamp.Value.ToFileTimeUtc());
            }

            if (dv.ServerTimestamp.HasValue)
            {
                sum += Coding.CodingSize(dv.ServerTimestamp.Value.ToFileTimeUtc());
            }

            return sum;
        }

        public static bool Encode(this MemoryBuffer mem, DataValue dv)
        {
            if (!mem.Encode(dv.GetEncodingMask())) { return false; }
            if (dv.Value != null)
            {
                if (!mem.VariantEncode(dv.Value)) { return false; }
            }

            if (dv.StatusCode.HasValue)
            {
                if (!mem.Encode((uint)dv.StatusCode.Value)) { return false; }
            }

            if (dv.SourceTimestamp.HasValue)
            {
                if (!mem.Encode(dv.SourceTimestamp.Value.ToFileTimeUtc())) { return false; }
            }

            if (dv.ServerTimestamp.HasValue)
            {
                if (!mem.Encode(dv.ServerTimestamp.Value.ToFileTimeUtc())) { return false; }
            }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out ReadValueId rv)
        {
            rv = null;


            if (!mem.Decode(out NodeId nodeId)) { return false; }
            if (!mem.Decode(out uint attributeId)) { return false; }
            if (!mem.DecodeUAString(out string indexRange)) { return false; }
            if (!mem.Decode(out QualifiedName dataEncoding)) { return false; }

            try
            {
                rv = new ReadValueId(nodeId, (NodeAttribute)attributeId, indexRange, dataEncoding);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ReadValueId rv)
        {
            if (!mem.Encode(rv.NodeId)) { return false; }
            if (!mem.Encode((UInt32)rv.AttributeId)) { return false; }
            if (!mem.EncodeUAString(rv.IndexRange)) { return false; }
            if (!mem.Encode(rv.DataEncoding)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out EndpointDescription ep)
        {
            ep = null;

            var UserIdentityTokens = new List<UserTokenPolicy>();

            if (!mem.DecodeUAString(out string EndpointUrl)) { return false; }
            if (!mem.Decode(out ApplicationDescription Server)) { return false; }
            if (!mem.DecodeUAByteString(out byte[] ServerCertificate)) { return false; }
            if (!mem.Decode(out uint SecurityMode)) { return false; }
            if (!mem.DecodeUAString(out string SecurityPolicyUri)) { return false; }
            if (!mem.DecodeArraySize(out uint numUserIdentityTokens)) { return false; }

            if (numUserIdentityTokens != 0xFFFFFFFFu)
            {
                for (uint i = 0; i < numUserIdentityTokens; i++)
                {

                    if (!mem.DecodeUAString(out string policyId)) { return false; }
                    if (!mem.Decode(out uint tokenType)) { return false; }
                    if (!mem.DecodeUAString(out string issuedTokenType)) { return false; }
                    if (!mem.DecodeUAString(out string issuerEndpointUrl)) { return false; }
                    if (!mem.DecodeUAString(out string securityPolicyUri)) { return false; }

                    try
                    {
                        UserIdentityTokens.Add(new UserTokenPolicy(policyId, (UserTokenType)tokenType, issuedTokenType, issuerEndpointUrl, securityPolicyUri));
                    }
                    catch
                    {
                        return false;
                    }
                }
            }

            if (!mem.DecodeUAString(out string TransportProfileUri)) { return false; }
            if (!mem.Decode(out byte SecurityLevel)) { return false; }

            try
            {
                ep = new EndpointDescription(EndpointUrl, Server, ServerCertificate, (MessageSecurityMode)SecurityMode, SecurityPolicyUri, UserIdentityTokens.ToArray(), TransportProfileUri, SecurityLevel);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, EndpointDescription ep)
        {
            if (!mem.EncodeUAString(ep.EndpointUrl)) { return false; }
            if (!mem.Encode(ep.Server)) { return false; }
            if (!mem.EncodeUAByteString(ep.ServerCertificate ?? new byte[0])) { return false; }
            if (!mem.Encode((UInt32)ep.SecurityMode)) { return false; }
            if (!mem.EncodeUAString(ep.SecurityPolicyUri)) { return false; }

            if (ep.UserIdentityTokens == null)
            {
                if (!mem.Encode((UInt32)0)) { return false; }
            }
            else
            {
                if (!mem.Encode((UInt32)ep.UserIdentityTokens.Length)) { return false; }

                for (uint i = 0; i < ep.UserIdentityTokens.Length; i++)
                {
                    if (!mem.EncodeUAString(ep.UserIdentityTokens[i].PolicyId)) { return false; }
                    if (!mem.Encode((UInt32)ep.UserIdentityTokens[i].TokenType)) { return false; }
                    if (!mem.EncodeUAString(ep.UserIdentityTokens[i].IssuedTokenType)) { return false; }
                    if (!mem.EncodeUAString(ep.UserIdentityTokens[i].IssuerEndpointUrl)) { return false; }
                    if (!mem.EncodeUAString(ep.UserIdentityTokens[i].SecurityPolicyUri)) { return false; }
                }
            }

            if (!mem.EncodeUAString(ep.TransportProfileUri)) { return false; }
            if (!mem.Encode(ep.SecurityLevel)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out ApplicationDescription ad)
        {
            ad = null;


            if (!mem.DecodeUAString(out string ApplicationUri)) { return false; }
            if (!mem.DecodeUAString(out string ProductUri)) { return false; }
            if (!mem.Decode(out LocalizedText ApplicationName)) { return false; }
            if (!mem.Decode(out uint Type)) { return false; }
            if (!mem.DecodeUAString(out string GatewayServerUri)) { return false; }
            if (!mem.DecodeUAString(out string DiscoveryProfileUri)) { return false; }
            if (!mem.DecodeUAString(out string[] DiscoveryUrls)) { return false; }

            try
            {
                ad = new ApplicationDescription(ApplicationUri, ProductUri, ApplicationName, (ApplicationType)Type, GatewayServerUri, DiscoveryProfileUri, DiscoveryUrls);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ApplicationDescription ad)
        {
            if (!mem.EncodeUAString(ad.ApplicationUri)) { return false; }
            if (!mem.EncodeUAString(ad.ProductUri)) { return false; }
            if (!mem.Encode(ad.ApplicationName)) { return false; }
            if (!mem.Encode((UInt32)ad.Type)) { return false; }
            if (!mem.EncodeUAString(ad.GatewayServerUri)) { return false; }
            if (!mem.EncodeUAString(ad.DiscoveryProfileUri)) { return false; }
            if (!mem.EncodeUAString(ad.DiscoveryUrls)) { return false; }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ApplicationDescription ad, string[] DiscoveryUrls)
        {
            if (!mem.EncodeUAString(ad.ApplicationUri)) { return false; }
            if (!mem.EncodeUAString(ad.ProductUri)) { return false; }
            if (!mem.Encode(ad.ApplicationName)) { return false; }
            if (!mem.Encode((UInt32)ad.Type)) { return false; }
            if (!mem.EncodeUAString(ad.GatewayServerUri)) { return false; }
            if (!mem.EncodeUAString(ad.DiscoveryProfileUri)) { return false; }
            if (!mem.EncodeUAString(DiscoveryUrls)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out QualifiedName qn)
        {
            qn = new QualifiedName();


            if (!mem.Decode(out ushort namespaceIndex)) { return false; }
            if (!mem.DecodeUAString(out string name)) { return false; }
            qn = new QualifiedName(namespaceIndex, name);

            return true;
        }

        public static int CodingSize(this MemoryBuffer mem, QualifiedName qn)
        {
            return Coding.CodingSize(qn.NamespaceIndex) + Coding.CodingSizeUAString(qn.Name);
        }

        public static bool Encode(this MemoryBuffer mem, QualifiedName qn)
        {
            if (!mem.Encode(qn.NamespaceIndex)) { return false; }
            if (!mem.EncodeUAString(qn.Name)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out LocalizedText ad)
        {
            ad = null;
            string Locale = string.Empty, Text = string.Empty;

            if (!mem.Decode(out byte mask)) { return false; }

            if ((mask & 1) != 0)
            {
                if (!mem.DecodeUAString(out Locale)) { return false; }
            }

            if ((mask & 2) != 0)
            {
                if (!mem.DecodeUAString(out Text)) { return false; }
            }

            ad = new LocalizedText(Locale, Text);

            return true;
        }

        public static int CodingSize(this MemoryBuffer mem, LocalizedText ad)
        {
            int size = Coding.CodingSize((byte)0);
            if (!string.IsNullOrEmpty(ad.Locale)) { size += Coding.CodingSizeUAString(ad.Locale); }
            if (!string.IsNullOrEmpty(ad.Text)) { size += Coding.CodingSizeUAString(ad.Text); }

            return size;
        }

        public static bool Encode(this MemoryBuffer mem, LocalizedText ad)
        {
            byte mask = 0;
            if (!string.IsNullOrEmpty(ad.Locale)) { mask |= 1; }
            if (!string.IsNullOrEmpty(ad.Text)) { mask |= 2; }

            if (!mem.Encode(mask)) { return false; }
            if (!string.IsNullOrEmpty(ad.Locale) && !mem.EncodeUAString(ad.Locale)) { return false; }
            if (!string.IsNullOrEmpty(ad.Text) && !mem.EncodeUAString(ad.Text)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out ResponseHeader resp)
        {
            resp = null;


            if (!mem.Decode(out ulong Timestamp)) { return false; }
            if (!mem.Decode(out uint RequestHandle)) { return false; }
            if (!mem.Decode(out uint ServiceResult)) { return false; }
            if (!mem.Decode(out byte ServiceDiagnosticsMask)) { return false; }
            if (!mem.DecodeUAString(out string[] StringTable)) { return false; }
            if (!mem.Decode(out ExtensionObject AdditionalHeader)) { return false; }

            resp = new ResponseHeader();
            try { resp.Timestamp = DateTimeOffset.FromFileTime((long)Timestamp); }
            catch { resp.Timestamp = DateTimeOffset.MinValue; }

            resp.RequestHandle = RequestHandle;
            resp.ServiceResult = ServiceResult;
            resp.ServiceDiagnosticsMask = ServiceDiagnosticsMask;
            resp.StringTable = StringTable;
            resp.AdditionalHeader = AdditionalHeader;

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ResponseHeader resp)
        {
            if (!mem.Encode(resp.Timestamp.ToFileTime())) { return false; }
            if (!mem.Encode(resp.RequestHandle)) { return false; }
            if (!mem.Encode(resp.ServiceResult)) { return false; }

            // Incomplete service diagnostics
            if (!mem.Encode((Byte)0)) { return false; }

            if (!mem.EncodeUAString(resp.StringTable)) { return false; }
            if (!mem.Encode(resp.AdditionalHeader)) { return false; }

            return true;
        }

        public static bool Decode(this MemoryBuffer mem, out RequestHeader req)
        {
            req = null;


            if (!mem.Decode(out NodeId AuthToken)) { return false; }
            if (!mem.Decode(out ulong Timestamp)) { return false; }
            if (!mem.Decode(out uint RequestHandle)) { return false; }
            if (!mem.Decode(out uint ReturnDiagnostics)) { return false; }
            if (!mem.DecodeUAString(out string AuditEntryId)) { return false; }
            if (!mem.Decode(out uint TimeoutHint)) { return false; }
            if (!mem.Decode(out ExtensionObject AdditionalHeader)) { return false; }

            req = new RequestHeader();
            try { req.Timestamp = DateTime.FromFileTimeUtc((long)Timestamp); }
            catch { req.Timestamp = DateTime.MinValue; }

            req.AuthToken = AuthToken;
            req.RequestHandle = RequestHandle;
            req.ReturnDiagnostics = ReturnDiagnostics;
            req.AuditEntryId = AuditEntryId;
            req.TimeoutHint = TimeoutHint;
            req.AdditionalHeader = AdditionalHeader;

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, RequestHeader req)
        {
            if (!mem.Encode(req.AuthToken)) { return false; }
            if (!mem.Encode((UInt64)req.Timestamp.ToFileTimeUtc())) { return false; }
            if (!mem.Encode(req.RequestHandle)) { return false; }
            if (!mem.Encode(req.ReturnDiagnostics)) { return false; }
            if (!mem.EncodeUAString(req.AuditEntryId)) { return false; }
            if (!mem.Encode(req.TimeoutHint)) { return false; }
            if (!mem.Encode(req.AdditionalHeader)) { return false; }

            return true;
        }

        public static int CodingSize(this MemoryBuffer mem, ExtensionObject obj)
        {
            int size = 0;

            if (obj == null)
            {
                size = Coding.CodingSize(NodeId.Zero);
                size += Coding.CodingSize((byte)ExtensionObjectBodyType.None);
                return size;
            }

            size += Coding.CodingSize(obj.TypeId);
            size += Coding.CodingSize((byte)ExtensionObjectBodyType.None);

            if (obj.Body == null)
            {
                return size;
            }

            size += Coding.CodingSizeUAByteString(obj.Body);

            return size;
        }

        public static bool Decode(this MemoryBuffer mem, out ExtensionObject obj)
        {
            obj = new ExtensionObject();

            if (!mem.Decode(out NodeId type)) { return false; }
            obj.TypeId = type;

            if (!mem.Decode(out byte mask)) { return false; }

            if (mask == (byte)ExtensionObjectBodyType.BodyIsByteString)
            {
                if (!mem.DecodeUAByteString(out byte[] str)) { return false; }
                obj.Body = str;
            }

            return true;
        }

        public static bool Encode(this MemoryBuffer mem, ExtensionObject obj)
        {
            if (obj == null)
            {
                if (!mem.Encode(NodeId.Zero)) { return false; }
                return mem.Encode((byte)ExtensionObjectBodyType.None);
            }

            if (!mem.Encode(obj.TypeId)) { return false; }

            if (obj.Body == null)
            {
                return mem.Encode((byte)ExtensionObjectBodyType.None);
            }
            else
            {
                if (!mem.Encode((byte)ExtensionObjectBodyType.BodyIsByteString)) { return false; }

                return mem.EncodeUAByteString(obj.Body);
            }

            throw new Exception("Encode extension objects must be byte[] or null");
        }

        public static bool Decode(this MemoryBuffer mem, out NodeId id)
        {
            id = null;

            if (!mem.Decode(out byte encodingMask))
            {
                return false;
            }

            switch (encodingMask & 0x3F)
            {
                case (byte)NodeIdType.TwoByte:
                    {
                        if (!mem.Decode(out byte addr)) { return false; }

                        if (((encodingMask & 0x40) != 0) && !mem.Decode(out UInt32 _)) { return false; }

                        id = new NodeId(0, addr);
                        return true;
                    }

                case (byte)NodeIdType.FourByte:
                    {
                        if (!mem.Decode(out byte ns)) { return false; }
                        if (!mem.Decode(out ushort addr)) { return false; }

                        if (((encodingMask & 0x40) != 0) && !mem.Decode(out UInt32 _)) { return false; }

                        id = new NodeId(ns, addr);
                        return true;
                    }

                case (byte)NodeIdType.Numeric:
                    {
                        if (!mem.Decode(out ushort ns)) { return false; }
                        if (!mem.Decode(out uint addr)) { return false; }

                        if (((encodingMask & 0x40) != 0) && !mem.Decode(out UInt32 _)) { return false; }

                        id = new NodeId(ns, addr);
                        return true;
                    }

                case (byte)NodeIdType.String:
                    {
                        if (!mem.Decode(out ushort ns)) { return false; }
                        if (!mem.DecodeUAString(out string addr)) { return false; }

                        if (((encodingMask & 0x40) != 0) && !mem.Decode(out UInt32 _)) { return false; }

                        id = new NodeId(ns, addr);
                        return true;
                    }

                case (byte)NodeIdType.ByteString:
                    {
                        if (!mem.Decode(out ushort ns)) { return false; }
                        if (!mem.DecodeUAByteString(out byte[] addr)) { return false; }

                        if (((encodingMask & 0x40) != 0) && !mem.Decode(out UInt32 _)) { return false; }

                        id = new NodeId(ns, addr, NodeIdNetType.ByteString);
                        return true;
                    }

                case (byte)NodeIdType.Guid:
                    {
                        if (!mem.Decode(out ushort ns)) { return false; }
                        if (!mem.DecodeUAGuidByteString(out byte[] addr)) { return false; }

                        if (((encodingMask & 0x40) != 0) && !mem.Decode(out UInt32 _)) { return false; }

                        id = new NodeId(ns, addr, NodeIdNetType.Guid);
                        return true;
                    }

                default:
                    // TODO: Handle
                    throw new Exception();
            }
        }

        public static bool Encode(this MemoryBuffer mem, NodeId id)
        {
            if (id == null)
            {
                return mem.Encode(NodeId.Zero);
            }

            switch (id.IdType)
            {
                case NodeIdNetType.Numeric:
                    {
                        if (id.NamespaceIndex == 0 && id.NumericIdentifier <= 0xFF)
                        {
                            if (!mem.Encode((Byte)NodeIdType.TwoByte)) { return false; }
                            if (!mem.Encode((Byte)id.NumericIdentifier)) { return false; }
                        }
                        else if (id.NamespaceIndex <= 0xFF && id.NumericIdentifier <= 0xFFFF)
                        {
                            if (!mem.Encode((Byte)NodeIdType.FourByte)) { return false; }
                            if (!mem.Encode((Byte)id.NamespaceIndex)) { return false; }
                            if (!mem.Encode((UInt16)id.NumericIdentifier)) { return false; }
                        }
                        else
                        {
                            if (!mem.Encode((Byte)NodeIdType.Numeric)) { return false; }
                            if (!mem.Encode((UInt16)id.NamespaceIndex)) { return false; }
                            if (!mem.Encode((UInt32)id.NumericIdentifier)) { return false; }
                        }

                        break;
                    }

                case NodeIdNetType.String:
                    {
                        if (!mem.Encode((Byte)NodeIdType.String)) { return false; }
                        if (!mem.Encode((UInt16)id.NamespaceIndex)) { return false; }
                        if (!mem.EncodeUAString(id.StringIdentifier)) { return false; }

                        break;
                    }

                case NodeIdNetType.ByteString:
                    {
                        if (!mem.Encode((Byte)NodeIdType.ByteString)) { return false; }
                        if (!mem.Encode((UInt16)id.NamespaceIndex)) { return false; }
                        if (!mem.EncodeUAByteString(id.ByteStringIdentifier)) { return false; }

                        break;
                    }

                case NodeIdNetType.Guid:
                    {
                        if (!mem.Encode((Byte)NodeIdType.Guid)) { return false; }
                        if (!mem.Encode((UInt16)id.NamespaceIndex)) { return false; }
                        if (!mem.EncodeUAGuidByteString(id.ByteStringIdentifier)) { return false; }

                        break;
                    }

                default:
                    // TODO: Handle
                    throw new Exception();
            }

            return true;
        }


        public static bool EncodeUAByteString(this MemoryBuffer mem, byte[] str)
        {
            if (str == null)
            {
                return mem.Encode((UInt32)0xFFFFFFFFu);
            }

            if (!mem.Encode((uint)str.Length))
            {
                return false;
            }

            if (str.Length > 0)
            {
                if (!mem.EnsureAvailable(str.Length, true)) { return false; }
                return mem.Append(str, str.Length);
            }

            return true;
        }

        public static bool DecodeUAByteString(this MemoryBuffer mem, out byte[] str)
        {
            str = null;
            if (!mem.Decode(out uint Length)) { return false; }

            if (Length == 0xFFFFFFFFu)
            {
                return true;
            }

            if (!mem.EnsureAvailable((int)Length, true))
            {
                return false;
            }

            if (Length == 0)
            {
                str = new byte[0];
                return true;
            }

            str = new byte[Length];
            Array.Copy(mem.Buffer, mem.Position, str, 0, Length);
            mem.Position += (int)Length;

            return true;
        }

        public static bool EncodeUAGuidByteString(this MemoryBuffer mem, byte[] str)
        {
            if (str == null || str.Length != 16)
            {
                return false;
            }

            if (!mem.EnsureAvailable(str.Length, true)) { return false; }
            return mem.Append(str, str.Length);
        }

        public static bool DecodeUAGuidByteString(this MemoryBuffer mem, out byte[] str)
        {
            UInt32 Length = 16;
            str = null;

            if (!mem.EnsureAvailable((int)Length, true))
            {
                return false;
            }

            str = new byte[Length];
            Array.Copy(mem.Buffer, mem.Position, str, 0, Length);
            mem.Position += (int)Length;

            return true;
        }

        public static bool EncodeUAString(this MemoryBuffer mem, string[] table)
        {
            if (table == null)
            {
                if (!mem.Encode((UInt32)0)) { return false; }
            }
            else
            {
                if (!mem.Encode((UInt32)table.Length)) { return false; }
                for (int i = 0; i < table.Length; i++)
                {
                    if (!mem.EncodeUAString(table[i])) { return false; }
                }
            }

            return true;
        }

        public static bool DecodeUAString(this MemoryBuffer mem, out string[] table)
        {
            table = null;
            if (!mem.Decode(out uint Length)) { return false; }

            if (Length == 0xFFFFFFFFu)
            {
                return true;
            }

            table = new string[Length];
            for (int i = 0; i < Length; i++)
            {
                mem.DecodeUAString(out table[i]);
            }

            return true;
        }



        public static bool EncodeUAString(this MemoryBuffer mem, string str)
        {
            if (str == null)
            {
                return mem.Encode((UInt32)0xFFFFFFFFu);
            }

            byte[] bytes = Encoding.UTF8.GetBytes(str);
            if (!mem.Encode((uint)bytes.Length))
            {
                return false;
            }

            if (str.Length > 0)
            {
                if (!mem.EnsureAvailable(bytes.Length, true)) { return false; }
                return mem.Append(bytes, bytes.Length);
            }

            return true;
        }

        public static bool DecodeUAString(this MemoryBuffer mem, out string str)
        {
            str = null;
            if (!mem.Decode(out uint Length)) { return false; }

            if (Length == 0xFFFFFFFFu)
            {
                return true;
            }

            var arr = new byte[Length];
            if (!mem.EnsureAvailable((int)Length, true))
            {
                return false;
            }

            if (Length == 0)
            {
                str = string.Empty;
                return true;
            }

            Array.Copy(mem.Buffer, mem.Position, arr, 0, Length);
            mem.Position += (int)Length;

            str = Encoding.UTF8.GetString(arr);
            return true;
        }
    }
}
