// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.XPath;

namespace LibUA.Security.Cryptography.Xml
{
    /// <summary>
    ///     <para>
    ///         XmlDsigXPathWithNamespacesTransform provides a version of the XPath transform which allows the
    ///         XPath expression to use the namespace mappings in scope at the point of the XML declaration of
    ///         the XPath expression. The standard XmlDsigXPathTransform requires that any namespaces being
    ///         used in the XPath expression be defined on the XPath node explicitly. This version of the
    ///         transform allows any namepsace in scope at the XPath node to be used, even if they are not
    ///         explicitly declared on the node itself.
    ///     </para>
    ///     <para>
    ///         In order to use this transform when signing, simply add it to the Reference section that
    ///         should be processed with the XPath expression. For example:
    ///     </para>
    ///     <example>
    ///         Reference reference = new Reference("");
    ///         reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
    ///
    ///         // Ensure that we can use the clrsec namespace in the XPath expression
    ///         Dictionary&lt;string, string&gt; additionalNamespaces = new Dictionary&lt;string, string&gt;();
    ///         additionalNamespaces ["clrsec"] = "http://www.codeplex.com/clrsecurity";
    ///         reference.AddTransform(new XmlDsigXPathWithNamespacesTransform("ancestor-or-self::node()[@clrsec:sign='true']", null, additionalNamespaces));
    ///     </example>
    ///     <para>
    ///         For verification purposes, machine.config must be setup to map the XPath transform URL to
    ///         XmlDsigXPathWithNamespacesTransform so that SignedXml creates this version of the XPath
    ///         transform when processing a signature.
    ///     </para>
    ///     <para>
    ///         Registration in CryptoConfig requires editing the machine.config file found in the .NET
    ///         Framework installation's configuration directory (such as
    ///         %WINDIR%\Microsoft.NET\Framework\v2.0.50727\Config or
    ///         %WINDIR%\Microsoft.NET\Framework64\v2.0.50727\Config) to include registration information on
    ///         the type. For example:
    ///     </para>
    ///     <example>
    ///         <![CDATA[
    ///           <configuration>
    ///             <mscorlib>
    ///               <cryptographySettings>
    ///                 <cryptoNameMapping>
    ///                   <cryptoClasses>
    ///                     <cryptoClass XmlDsigXPathWithNamespacesTransform="Security.Cryptography.Xml.XmlDsigXPathWithNamespacesTransform, Security.Cryptography, Version=1.4.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
    ///                   </cryptoClasses>
    ///                   <nameEntry name="http://www.w3.org/TR/1999/REC-xpath-19991116" class="XmlDsigXPathWithNamespacesTransform" />
    ///                 </cryptoNameMapping>
    ///               </cryptographySettings>
    ///             </mscorlib>
    ///           </configuration>    
    ///         ]]>
    ///     </example>
    ///     <para>
    ///         After adding this registration entry, the assembly which contains the
    ///         XmlDsigXPathWithNamespacesTransform (in the example above Security.Cryptography.dll) needs to
    ///         be added to the GAC.
    ///     </para>
    ///     <para>  
    ///         Note that on 64 bit machines, both the Framework and Framework64 machine.config files should
    ///         be updated, and if the signature description assembly is built bit-specific it needs to be
    ///         added to both the 32 and 64 bit GACs.
    ///     </para>
    ///     <para>
    ///         See http://www.w3.org/TR/xmldsig-core/#sec-XPath for more information on the XPath transform.
    ///     </para>
    ///     <para>
    ///         Since most of the XmlDsigXPathWithNamespacesTransform APIs are inherited from the
    ///         <see cref="XmlDsigXPathTransform" /> base class, please see the MSDN documentation for
    ///         XmlDsigXPathTransform for a complete list of the methods and properties available on
    ///         XmlDsigXPathWithNamespacesTransform.
    ///     </para>
    /// </summary>
    [SuppressMessage("Microsoft.Naming", "CA1702:CompoundWordsShouldBeCasedCorrectly", MessageId = "XPath", Justification = "This matches the XPath spelling in the rest of the framework.")]
    public sealed class XmlDsigXPathWithNamespacesTransform : XmlDsigXPathTransform
    {
        private XmlDocument m_inputNodes;
        private IDictionary<string, string> m_namespaces;
        private string m_xpathExpression;

        /// <summary>
        ///     Constructs an XmlDsigXPathWithNamespacesTransform object without an initial XPath query or
        ///     namespaces.  This constructor should not be used, and is provided so that the type may be
        ///     instantiated from CryptoConfig.
        /// </summary>
        public XmlDsigXPathWithNamespacesTransform()
        {
        }

        /// <summary>
        ///     Constructs an XmlDsigXPathWithNamespacesTransform object which will apply the given XPath
        ///     expression when it is invoked. No XML namespaces will be brought into scope for use in the
        ///     query.
        /// </summary>
        /// <param name="xpath">xpath expression to use in this transform</param>
        /// <exception cref="ArgumentNullException">if <paramref name="xpath" /> is null</exception>
        public XmlDsigXPathWithNamespacesTransform(string xpath) : this(xpath, null)
        {
        }

        /// <summary>
        ///     Constructs an XmlDsigXPathWithNamespacesTransform object which will apply the given XPath
        ///     expression when it is invoked. Any namespace mappings in the explicitNamespaces dictionary
        ///     will be available for use in the XPath expression and will also be added to the XPath node in
        ///     the transform's XML, which allows the transform to be processed by the standard
        ///     XmlDsigXPathTransform.
        /// </summary>
        /// <param name="xpath">xpath expression to use in this transform</param>
        /// <param name="explicitNamespaces">
        ///     namespaces mappings to add directly to the XPath portion of the transform
        /// </param>
        /// <exception cref="ArgumentNullException">if <paramref name="xpath" /> is null</exception>
        public XmlDsigXPathWithNamespacesTransform(string xpath,
                                                   IDictionary<string, string> explicitNamespaces)
            : this(xpath, explicitNamespaces, null)
        {
        }

        /// <summary>
        ///     Constructs an XmlDsigXPathWithNamespacesTransform object which will apply the given XPath
        ///     expression when it is invoked. Any namespace mappings in the explicitNamespaces dictionary
        ///     will be available for use in the XPath expression and will also be added to the XPath node in
        ///     the transform's XML, which allows the transform to be processed by the standard
        ///     XmlDsigXPathTransform. The additionalNamespaces dictionary provides namespace mappings which
        ///     will be available during signing but which will not be added to the XPath node of the
        ///     transform. These namespaces will need to be in scope from elsewhere in the XML document during
        ///     verification for the transform to succeed.
        /// </summary>
        /// <param name="xpath">xpath expression to use in this transform</param>
        /// <param name="explicitNamespaces">
        ///     namespaces mappings to add directly to the XPath portion of the transform
        /// </param>
        /// <param name="additionalNamespaces">
        ///     namespaces to use while signing, but not to bring into scope explicitly on the XPath portion
        ///     of the transform
        /// </param>
        /// <exception cref="ArgumentNullException">if <paramref name="xpath" /> is null</exception>
        public XmlDsigXPathWithNamespacesTransform(string xpath,
                                                   IDictionary<string, string> explicitNamespaces,
                                                   IDictionary<string, string> additionalNamespaces)
        {
            if (xpath == null)
                throw new ArgumentNullException("xpath");

            // Although we could initialize ourselves directly, there's no good way to initialize the base
            // XPath transform without going through XML.  Since we can also initialize via XML, we will
            // just piggyback on that to keep all initialization code centralized.
            XmlDocument doc = new XmlDocument();

            XmlElement rootElement = doc.CreateElement("XPathRoot");

            // Put the additional namespaces on a root element of the XPath element, so that we don't add them
            // to the XML that will be generated for this transform.  We need to put them on a parent node
            // so that they are in scope for signautre generation when the XPath node isn't yet attached to
            // its context document.
            if (additionalNamespaces != null)
            {
                foreach (string namespaceAlais in additionalNamespaces.Keys)
                {
                    XmlAttribute namespaceDeclaration = doc.CreateAttribute("xmlns",
                                                                            namespaceAlais,
                                                                            "http://www.w3.org/2000/xmlns/");
                    namespaceDeclaration.Value = additionalNamespaces[namespaceAlais];
                    rootElement.Attributes.Append(namespaceDeclaration);
                }
            }

            XmlElement xpathElement = doc.CreateElement("XPath");
            xpathElement.InnerText = xpath;

            // Explicit namespaces need to be added directly to the XPath node itself so that they end up in
            // the produced XML.
            if (explicitNamespaces != null)
            {
                foreach (string namespaceAlais in explicitNamespaces.Keys)
                {
                    XmlAttribute namespaceDeclaration = doc.CreateAttribute("xmlns",
                                                                            namespaceAlais,
                                                                            "http://www.w3.org/2000/xmlns/");
                    namespaceDeclaration.Value = explicitNamespaces[namespaceAlais];
                    xpathElement.Attributes.Append(namespaceDeclaration);
                }
            }

            rootElement.AppendChild(xpathElement);

            LoadInnerXml(xpathElement.SelectNodes("."));
        }

        /// <summary>
        ///     Build a transform from its XML representation
        /// </summary>
        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            base.LoadInnerXml(nodeList);

            // XmlDSigXPathTransform.LoadInput will thow on null input
            Debug.Assert(nodeList != null, "nodeList != null");

            // XmlDsigXpathTransform does not expose the XPath expression or the namespaces that are added
            // on the XPath node itself, so we need to look for them ourselves.
            for (int i = 0; i < nodeList.Count && m_xpathExpression == null; ++i)
            {
                // Only look for XPath elements
                XmlElement currentElement = nodeList[i] as XmlElement;
                if (currentElement != null && String.Equals(currentElement.LocalName, "XPath", StringComparison.Ordinal))
                {
                    // The XPath expression is the inner text of the XPath node
                    m_xpathExpression = currentElement.InnerXml.Trim();

                    // Get any namespace mappings in scope for the XPath element so that we can use those
                    // when the XPath is evaluated.
                    m_namespaces = currentElement.CreateNavigator().GetNamespacesInScope(XmlNamespaceScope.All);
                }
            }

            // XmlDSigXPathTransform should have failed when loading it's inner XML if we did not have an
            // inner XPath expression, which means if we got here we should have also been able to find the
            // expression.
            Debug.Assert(m_xpathExpression != null, "m_xpathExpression != null");
        }

        /// <summary>
        ///     Load input nodes to process
        /// </summary>
        public override void LoadInput(object obj)
        {
            if (obj == null)
                throw new ArgumentNullException("obj");

            // Canonicalize the input into a stream
            XmlDsigC14NTransform canonicalization = new XmlDsigC14NTransform(true);
            canonicalization.LoadInput(obj);
            Stream canonicalizedInput = canonicalization.GetOutput(typeof(Stream)) as Stream;

            // Load the canonicalized input into a document to transform
            XmlDocument document = new XmlDocument();
            document.Load(canonicalizedInput);
            m_inputNodes = document;
        }

        /// <summary>
        ///     Get the output of running the XPath expression on the input nodes
        /// </summary>
        public override object GetOutput()
        {
            XmlDSigNodeList outputNodes = new XmlDSigNodeList();

            // Only do work if we've been loaded with both an XPath expression as well as a list of input
            // nodes to transform
            if (m_xpathExpression != null && m_inputNodes != null)
            {
                XPathNavigator navigator = m_inputNodes.CreateNavigator();

                // Build up an expression for the XPath the transform specified and hook up the namespace
                // resolver which will resolve namsepaces against the original XPath expression's XML context.
                XPathExpression transformExpression = navigator.Compile(
                    String.Format(CultureInfo.InvariantCulture, "boolean({0})", m_xpathExpression));

                // Get the namespaces into scope for use in the expression
                XmlNamespaceManager namespaceManager = new XmlNamespaceManager(m_inputNodes.NameTable);
                foreach (KeyValuePair<string, string> namespaceDeclaration in m_namespaces)
                {
                    namespaceManager.AddNamespace(namespaceDeclaration.Key, namespaceDeclaration.Value);
                }
                transformExpression.SetContext(namespaceManager);

                // Iterate over the input nodes, applying the XPath expression to each.  If the XPath
                // expression returns true for the node, then add it to the output NodeList
                XPathNodeIterator inputNodeIterator = navigator.Select("//. | //@*");
                while (inputNodeIterator.MoveNext())
                {
                    XPathNavigator current = inputNodeIterator.Current;
                    if ((bool)current.Evaluate(transformExpression))
                    {
                        outputNodes.Add((current as IHasXmlNode).GetNode());
                    }
                }
            }

            return outputNodes;
        }
    }
}
