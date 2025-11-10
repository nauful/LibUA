// Copyright (c) Microsoft Corporation.  All rights reserved.

using System.Collections;
using System.Collections.Generic;
using System.Xml;

namespace LibUA.Security.Cryptography.Xml
{
    /// <summary>
    ///     Basic implementation of an XmlNodeList
    /// </summary>
    internal sealed class XmlDSigNodeList : XmlNodeList
    {
        private readonly List<XmlNode> m_list = new List<XmlNode>();

        public override int Count
        {
            get { return m_list.Count; }
        }

        public void Add(XmlNode node)
        {
            m_list.Add(node);
        }

        public override IEnumerator GetEnumerator()
        {
            return m_list.GetEnumerator();
        }

        public override XmlNode Item(int index)
        {
            return m_list[index];
        }
    }
}
