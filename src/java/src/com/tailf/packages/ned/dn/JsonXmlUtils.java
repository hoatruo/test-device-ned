package com.tailf.packages.ned.dn;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.json.XML;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class JsonXmlUtils {

    private static Logger logger = Logger.getLogger(JsonXmlUtils.class);

    private JsonXmlUtils() {

    }

    /**
     * This method converts XML string into {@link Document} object.
     *
     * @param xmlSource
     *            input String as XML representation
     * @return return the {@link Document} object
     * @throws SAXException
     * @throws ParserConfigurationException
     * @throws IOException
     */
    public static Document stringToDocument(String xmlSource)
            throws SAXException, ParserConfigurationException, IOException {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(
                new StringReader(xmlSource)));
        doc.setXmlStandalone(true);
        return doc;
    }

    /**
     * This method converts the {@link Document} object to XML String.
     *
     * @param doc
     *            input document to be convert to string
     * @return return the converted document as string
     * @throws TransformerException
     */
    public static String documentToString(Document doc)
            throws TransformerException {

        StringWriter sw = new StringWriter();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }

    /**
     * Converts given XML representation file object into Document object
     *
     * @param file
     *            input XML file object
     * @return Document object
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     */
    public static Document fileToDocument(File file)
            throws ParserConfigurationException, SAXException, IOException {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(file);
        doc.setXmlStandalone(true);
        return doc;

    }

    /**
     * Formats given XML String.
     *
     * @param xmlString
     * @return
     * @throws Exception
     */
    public static final String formatXMLString(String xmlString)
            throws Exception {
        Document doc = stringToDocument(xmlString);
        Transformer tf = TransformerFactory.newInstance().newTransformer();
        tf.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        tf.setOutputProperty(OutputKeys.INDENT, "yes");
        tf.setOutputProperty(OutputKeys.METHOD, "xml");
        tf.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
        tf.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        Writer out = new StringWriter();
        tf.transform(new DOMSource(doc), new StreamResult(out));
        return out.toString();
    }

    /**
     * Converts stream to string.
     *
     * @param input
     *            inputStream
     * @return converted string
     * @throws IOException
     */
    public static String convertStreamToString(InputStream input)
            throws IOException {
        BufferedReader reader = new BufferedReader(new
                InputStreamReader(input));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = reader.readLine()) != null) {
            response.append(inputLine);
        }
        reader.close();
        return response.toString();
    }

    /**
     * Converts given json String to XML string.
     *
     * @param inputJson
     * @param rootTag
     * @return
     */
    public static String convertJsonToXML(String inputJson, String rootTag)
            throws Exception {
        String xml = null;
        try {
            JSONObject json = new JSONObject(inputJson);
            xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" "
                    + "standalone=\"yes\"?>" + "<" + rootTag + ">"
                    + XML.toString(json) + "</" + rootTag + ">";
        } catch (Exception e) {
            logger.error("JsonToXML exception");
            throw e;
        }
        return xml;
    }
    /**
     * Converts given XML String to JSON string.
     *
     * @param inputXml
     * @return
     */
    public static String convertXmlToJson(String inputXml) {
        String json = null;
        try {
            JSONObject jsonObject = XML.toJSONObject(inputXml);
            json = jsonObject.toString(2);
            jsonObject.get("");
        } catch (Exception e) {
            return json;
        }
        return json;
    }

}
