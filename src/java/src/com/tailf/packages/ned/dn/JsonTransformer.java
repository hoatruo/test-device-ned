package com.tailf.packages.ned.dn;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.XML;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.tailf.ned.NedWorker;


/**
 * Implements the JSON transformer
 *
 * TODO: This class is used to tranfrom between NCS XML and device specific JSON
 *
 */
public class JsonTransformer {
    private static Logger log = Logger.getLogger(JsonTransformer.class);
    private static String PREFIX  = "dn:";
    private String deviceId;
    private boolean trace;

    enum Op {
        SORT_NODE_FIRST,
        STRIP_ATTRIBUTES,
        STRIP_META_DATA
    };


    public class deviceInfo {
        public String name;
        public String version;
        public String model;

        public deviceInfo() {

        }
    }


    /**
     * Implements the JsonTransformer constructor
     * @param deviceId - device identity
     */
    public JsonTransformer(String deviceId, boolean trace) {
        log.debug("JSON TRANSFORMER ==>");
        this.deviceId = deviceId;
        this.trace = trace;
        log.debug("JSON TRANSFORMER OK");
    }


    /**
     * Utility routine that recursively traverses a node tree and
     * performs operations on nodes that match a criteria.
     *
     * @param node   - current top node
     * @param op     - operations to perform
     * @param value  - value (match criteria)
     */
    @SuppressWarnings("unchecked")
    private void
    modify(Node node, Op op, Object value, Object data) {

        NodeList nodeList = node.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node currentNode = nodeList.item(i);
            modify(currentNode, op, value, data);
        }

        if (node.getNodeType() != Node.ELEMENT_NODE) {
            return;
        }

        switch (op) {

        case SORT_NODE_FIRST:

            /*
             * If node name matches name argument then
             * sort it as first child of the parent.
             */
            List<String> tags = (List<String>)value;
            if (tags.contains(node.getNodeName())) {
                Node parent = node.getParentNode();
                parent.insertBefore(node, parent.getFirstChild());
            }
            break;

        case STRIP_ATTRIBUTES:

            /*
             * Brutally remove all attributes
             */
            if (node.hasAttributes()) {
                NamedNodeMap attributes = node.getAttributes();
                Element e = (Element)node;

                for (int j = 0; j < attributes.getLength(); j++) {
                    e.removeAttribute(attributes.item(j).getNodeName());
                }
            }
            break;

        case STRIP_META_DATA:

            /*
             * Remove all nodes names "NED-META"
             */
            if (node.getNodeName().equals("NED-META")) {
                node.getParentNode().removeChild(node);
            }
            break;

        default:
            break;
        }
    }


    /**
     * Uses a simple XSLT to strip the xml dump from duplicates.
     * The ConfXMParam class does not like duplicates when converting
     * to ConfXMLParam array.
     * This routine can be removed when this issue has been solved.
     * @param input - XML dump
     * @param root - Root Element
     * @return New cleaned XML dump
     * @throws Exception
     */
    private String stripDuplicates(String input, String root)
        throws Exception {
        root = root.replaceAll("\\{.*\\}", "");

        String XSL = "<xsl:stylesheet version=\"1.0\" "
                   + "xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">"
                   + "<xsl:output omit-xml-declaration=\"yes\" indent=\"yes\"/>"
                   + "<xsl:strip-space elements=\"*\"/>"
                   + "<xsl:key name=\"ById\" match=\""
                   + root + "\" use=\"name\"/>"
                   + "<xsl:template match=\"node()|@*\">"
                   + "<xsl:copy>"
                   + "<xsl:apply-templates select=\"node()|@*\"/>"
                   + "</xsl:copy>"
                   + "</xsl:template>"
                   + "<xsl:template match="
                   + "\"" + root
                   + "[not(generate-id() = generate-id(key('ById', name)[1]))]\"/>"
                   + "</xsl:stylesheet>";

        TransformerFactory factory = TransformerFactory.newInstance();
        StreamSource xslStream = new StreamSource(new StringReader(XSL));
        Transformer transformer = factory.newTransformer(xslStream);
        StreamSource in = new StreamSource(new StringReader(input));
        StringWriter out = new StringWriter();

        transformer.transform(in, new StreamResult(out));

        return out.getBuffer().toString();
    }


    /**
     * Builds an NCS compliant XML formatted string out of a
     * JSON formatted string.
     *
     * @param path - the top path in the YANG model.
     * @param json - the JSON formatted string
     *
     * @return a XML formatted string
     *
     * @throws Exception
     */
    private String buildXML (String name, String json, List<String> keyTags)
        throws Exception {

        JSONObject o;
        if (json == null || json.equals("[]") || json.equals("{}")) {
            return null;
        }

        DocumentBuilder db =
            DocumentBuilderFactory.newInstance().newDocumentBuilder();
        InputSource is = new InputSource();

        /*
         * If JSON dump starts with "[" it is a JSON Array without name.
         * We need to add a name before converting it to XML.
         * {<name> : [....]}
         */
        if (json.trim().startsWith("[")) {
            /*
             * This is a plain JSON array without name.
             * Need to add a top element to it before converting it.
             */
            JSONArray a = new JSONArray(json);
            o = new JSONObject();
            o.put(name, a);
        }
        else {
            o = new JSONObject(json);
        }

        /*
         * Convert JSON to raw XML
         */
        String rawXml = XML.toString(o, "top");
        is.setCharacterStream(new StringReader(rawXml));

        /*
         * Modify XML data using standard DOM methods.
         */
        Document doc = db.parse(is);

        /*
         * Sort key tags first in all list elements
         */
        if (!keyTags.isEmpty()) {
            modify(doc.getDocumentElement(), Op.SORT_NODE_FIRST, keyTags, null);
        }

        /*
         * Generate the XML formated string.
         */
        StringWriter out = new StringWriter();
        TransformerFactory.newInstance().newTransformer().transform(
              new DOMSource(doc.getDocumentElement()),
              new StreamResult(out));

        return stripDuplicates(out.getBuffer().toString(), name);
    }


    /**
     * Builds a device compliant JSON formatted string out of a
     * a NCS generated XML string.
     *
     * @param root - the top path in the YANG model.
     * @param xml  - the NCS generated XML formatted string
     * @param keyTags - list with names of key elements
     *
     * @return a JSON formatted string
     *
     * @throws Exception
     */
    private String buildJSON (String xml)
        throws Exception {
        DocumentBuilderFactory df = DocumentBuilderFactory.newInstance();
        df.setNamespaceAware(false);
        DocumentBuilder db = df.newDocumentBuilder();
        InputSource is = new InputSource();

        is.setCharacterStream(new StringReader(xml.replace(PREFIX,"")));

        /*
         * Modify XML data using standard DOM methods.
         */
        Document src = db.parse(is);
        Document dst = db.newDocument();

        /*
         * Skip all headers above the actual config
         */
        Node config = src.getDocumentElement();

        if (config == null) {
            return null;
        }
        /*
         * Import into new document
         */
        config = dst.importNode(config, true);
        dst.appendChild(config);

        /*
         * Strip the NED private meta data tags from the xml
         */
        modify(dst.getDocumentElement(), Op.STRIP_META_DATA, null, null);

        /*
         * Strip xml attributes on all nodes.
         */
        modify(dst.getDocumentElement(), Op.STRIP_ATTRIBUTES, null, null);

        /*
         * Generate the JSON formated string.
         */
        StringWriter outXML = new StringWriter();
        TransformerFactory.newInstance().newTransformer().transform(
              new DOMSource(dst.getDocumentElement()),
              new StreamResult(outXML));

        JSONObject o = XML.toJSONObject(outXML.getBuffer().toString());


        /*
         * Relevant config is in the top JSON object.
         */
        o = o.getJSONObject("fragment");

        String json = o.toString(4).replace(PREFIX, "");

        return json.equals("[]") ? null : json;
    }


    /**
     * Simple pretty print utility for XML formatted strings
     * @param rawXml - raw XML dump
     * @return pretty printed XML
     */
    private String
    prettyPrintXML(String rawXml) {

        try {
            TransformerFactory transformerFactory = TransformerFactory.
                newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.
            setOutputProperty("{http://xml.apache.org/xslt}indent-amount",
                              String.valueOf(4));

            Source xmlInput = new StreamSource(new StringReader(rawXml));
            StringWriter stringWriter = new StringWriter();
            StreamResult xmlOutput = new StreamResult(stringWriter);

            transformer.transform(xmlInput, xmlOutput);
            return xmlOutput.getWriter().toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }


    /**
     * Converts a JSON formatted string into a XML formatted and
     * NCS compliant string.
     *
     * @param worker - current worker thread
     * @param path   - the top path in the YANG model
     * @param json   - the JSON formmated string
     *
     * @return XML formatted string
     *
     * @throws Exception
     */
    public String JsonToXml(NedWorker worker, String name,
                            String json, List<String> keyTags)
        throws Exception {
        log.debug("JSON TRANSFORMER JSONTOXML ==>");
        String XML = buildXML(name, json, keyTags);
        log.debug("JSON TRANSFORMER JSONTOXML OK");

        if (trace && XML != null) {
            worker.trace("\nXML output : " + prettyPrintXML(XML),
                         "in",
                         deviceId);
        }

        return XML;
    }


    /**
     * Converts a XMl formatted string into a JSON formatted and
     * device compliant string.
     *
     * @param worker - current worker thread
     * @param xml    - the NCS generated XML formated string
     *
     * @return JSON formatted string
     *
     * @throws Exception
     */
    public String XmlToJson(NedWorker worker, String xml)
        throws Exception {
        log.debug("JSON TRANSFORMER XMLTOJSON ==>");
        xml = xml.replaceAll("devname:", "");
        String JSON = buildJSON(xml);
        log.debug("JSON TRANSFORMER XMLTOJSON OK");

        if (trace && JSON != null) {
            worker.trace("\nJSON output : " + JSON, "out", deviceId);
        }

        return JSON;
    }

    /**
     * Extracts the UUID information from a JSON dump.
     * @param worker - Worker thread
     * @param json   - The JSON dump
     *
     * @return The UUID
     */
    public String getUUID(NedWorker worker, String json) {

        JSONObject o = new JSONObject(json);

       if (o.get("id") instanceof String)
           return o.getString("id");
       else
           return Long.toString(o.getLong("id"));
    }
}

