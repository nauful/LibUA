// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using LibUA.Security.Cryptography.Xml;
using System.Xml;
using System.Security.Cryptography.Xml;

namespace LibUA.Security.Cryptography.Xml
{
    /// <summary>
    ///     The TransformFactory class provides helper methods for programmatically creating transforms for
    ///     use with the <see cref="SignedXml" /> class. Since many of the transforms do not have constructors
    ///     or other method that allow them to be created easily in code when creating an XML signature, they
    ///     generally have to be constructed via XML. TransformFactory provides APIs that allow you to create
    ///     these transforms without having to directly create the XML for the transform by hand.
    /// </summary>
    public static class TransformFactory
    {
        /// <summary>
        ///     Creates an XPath transform for the given XPath query. The transform created from this method
        ///     does not bring any XML namespaces into scope, so the XPath query must not rely on any XML
        ///     namespaces from the XML being signed.
        /// </summary>
        /// <param name="xpath">XPath query to embed into the transform</param>
        /// <exception cref="ArgumentNullException">if <paramref name="xpath"/> is null</exception>
        [SuppressMessage("Microsoft.Naming", "CA1702:CompoundWordsShouldBeCasedCorrectly", MessageId = "XPath", Justification = "This matches the XPath spelling in the rest of the framework.")]
        public static XmlDsigXPathTransform CreateXPathTransform(string xpath)
        {
            return CreateXPathTransform(xpath, null);
        }

        /// <summary>
        ///     <para>
        ///         Creates an XPath transform for the given XPath query. If <paramref name="namespaces" />
        ///         is provided, it should contain mappings of XML namespace prefixes to namespace URIs. Each
        ///         key in the dictionary will be interpreted as a prefix corresponding to the value's URI.
        ///     </para>
        ///     <para>
        ///         The XPath query can rely upon the namespaces brought into scope by the
        ///         <paramref name="namespaces" /> dictionary, but not any other namespaces in the XML being
        ///         signed.
        ///     </para>
        /// </summary>
        /// <param name="xpath">XPath query to embed into the transform</param>
        /// <param name="namespaces">optional XML namespace mappings to bring into scope for the query</param>
        /// <exception cref="ArgumentNullException">if <paramref name="xpath"/> is null</exception>
        [SuppressMessage("Microsoft.Naming", "CA1702:CompoundWordsShouldBeCasedCorrectly", MessageId = "XPath", Justification = "This matches the XPath spelling in the rest of the framework.")]
        public static XmlDsigXPathTransform CreateXPathTransform(string xpath, IDictionary<string, string> namespaces)
        {
            if (xpath == null)
                throw new ArgumentNullException("xpath");

            // XmlDsigXPath transform only sets its XPath query when it loads itself from XML.  In order to
            // setup the transform, we'll build up XML representing the transform, and then load that XML
            // into the transform.
            XmlDocument doc = new XmlDocument();
            XmlElement xpathElement = doc.CreateElement("XPath");

            // The XPath query is the text value of the XPath node of the transform.
            xpathElement.InnerText = xpath;

            // Add the namespaces that should be in scope for the XPath expression.
            if (namespaces != null)
            {
                foreach (string namespaceAlais in namespaces.Keys)
                {
                    // Namespaces in scope for the XPath query must be declared on the XPath element.  For
                    // each namespace mapping, generate a namespace declaration attribute to apply to the
                    // XPath element.
                    XmlAttribute namespaceDeclaration = doc.CreateAttribute("xmlns",
                                                                            namespaceAlais,
                                                                            "http://www.w3.org/2000/xmlns/");
                    namespaceDeclaration.Value = namespaces[namespaceAlais];
                    xpathElement.Attributes.Append(namespaceDeclaration);
                }
            }

            // Build a transform from the XML representation
            XmlDsigXPathTransform xpathTransform = new XmlDsigXPathTransform();
            xpathTransform.LoadInnerXml(xpathElement.SelectNodes("."));

            return xpathTransform;
        }
    }
}
