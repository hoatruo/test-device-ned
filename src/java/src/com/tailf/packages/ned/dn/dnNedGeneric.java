/**
 *
 */
package com.tailf.packages.ned.dn;

import com.tailf.packages.ned.dn.namespaces.*;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.lang.reflect.Method;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.tailf.cdb.Cdb;
import com.tailf.cdb.CdbDBType;
import com.tailf.cdb.CdbSession;
import com.tailf.conf.Conf;
import com.tailf.conf.ConfBinary;
import com.tailf.conf.ConfBuf;
import com.tailf.conf.ConfException;
import com.tailf.conf.ConfKey;
import com.tailf.conf.ConfPath;
import com.tailf.conf.ConfValue;
import com.tailf.conf.ConfXMLParam;
import com.tailf.conf.ConfXMLParamStart;
import com.tailf.conf.ConfXMLParamStop;
import com.tailf.conf.ConfXMLParamValue;
import com.tailf.maapi.Maapi;
import com.tailf.maapi.MaapiConfigFlag;
import com.tailf.maapi.MaapiSchemas;
import com.tailf.maapi.MaapiSchemas.CSNode;
import com.tailf.navu.NavuContainer;
import com.tailf.navu.NavuContext;
import com.tailf.navu.NavuException;
import com.tailf.navu.NavuLeaf;
import com.tailf.navu.NavuList;
import com.tailf.navu.NavuListEntry;
import com.tailf.navu.NavuNode;
import com.tailf.ncs.ResourceManager;
import com.tailf.ncs.annotations.Resource;
import com.tailf.ncs.annotations.ResourceType;
import com.tailf.ncs.annotations.Scope;
import com.tailf.ncs.ns.Ncs;
import com.tailf.ned.NedCapability;
import com.tailf.ned.NedCmd;
import com.tailf.ned.NedEditOp;
import com.tailf.ned.NedException;
import com.tailf.ned.NedGenericBase;
import com.tailf.ned.NedMux;
import com.tailf.ned.NedTTL;
import com.tailf.ned.NedWorker;
import com.tailf.ned.NedWorker.TransactionIdMode;


public class dnNedGeneric extends NedGenericBase  {

    private static final String IDENTITY = "http://tail-f.com/ned/devname";
    private static final String MODULE   = "devname";
    private static final String TYPE     = "generic";
    private static final String PREFIX   = "dn:";
    private static final String DATE     = "2018-11-12";
    private static final String VERSION  = "1.0.0";
    private static final TransactionIdMode TRANS_ID_MODE =
        TransactionIdMode.NONE;
    private static final EnumSet<MaapiConfigFlag> cmdflagsConfig = EnumSet.of(
            MaapiConfigFlag.MAAPI_CONFIG_XML,
            MaapiConfigFlag.MAAPI_CONFIG_MERGE,
            MaapiConfigFlag.MAAPI_CONFIG_WITH_OPER,
            MaapiConfigFlag.MAAPI_CONFIG_XML_LOAD_LAX);


    private final static boolean WANT_REVERSE = true; // Needed for revert()

    private String       user;
    private String  	 password;
    private String       deviceId;
    private InetAddress  ip;
    private int          port;
    private String       luser;
    private boolean      trace;
    private int          connectTimeout; // msec
    private int          readTimeout;    // msec
    private int          writeTimeout;   // msec
    private String       ncsPrefix;
    private String       baseUrl = "";
    private String       apiKey = "";
    private boolean      useSSL = false;
    private boolean      acceptAny = false;
    private byte[]       cert = null;

    // private static CdbSession  cdbOper;

    private static Logger logger = Logger.getLogger(dnNedGeneric.class);
    private RESTConnection connection;
    private JsonTransformer transformer;

    NedCapability[]     capas = new NedCapability[2];
    NedCapability[]     stats_capas = new NedCapability[1];

    // Connects to the NcsServer and sets maapi
    @Resource(type=ResourceType.MAAPI, scope=Scope.INSTANCE)
    public  Maapi maapi;

    @Resource(type=ResourceType.CDB, scope=Scope.INSTANCE)
    public Cdb cdb;

    /**
     * Wrapper class for calculating valid device HTTP REST paths and
     * methods.
     *
     */
    private class RESTHttp {
        private String path;
        private String method = "default";

        RESTHttp(NavuNode node, Boolean withId, String action)
            throws NavuException {

            /*
             * Build path as it should be. Key names replaced with UUIDs etc.
             */
            path = doPath(node, withId ? null : node);

            /*
             * There are a number of inconsistencies in the MERAKI REST API.
             * This code deals with them. Each inconsisteny is stored
             * as meta-data in the YANG schema.
             */
            String meta = getMetaData(node);

            if (meta == null || meta.indexOf(action) < 0) {
                logger.debug("No meta data available for " + node.getKeyPath());
                return;
            }

            int firstIndex = meta.indexOf(action) + action.length() + 1;
            int lastIndex = meta.indexOf(";", firstIndex);
            if (lastIndex < 0) {
                lastIndex=meta.length();
            }

            String cmds[] = meta.substring(firstIndex, lastIndex).split(",");

            for (String cmd : cmds) {
                if (cmd.equals("trim-path")) {
                    /*
                     * Trim /organizations/zzzzz from the REST path
                     */
                    path = path.substring(path.indexOf("/networks"),
                                          path.length());
                } else if (cmd.startsWith("append")) {
                    /*
                     * Append extra string to the REST path
                     */
                    path = path + cmd.substring(cmd.indexOf("=") + 1,
                                                cmd.length());
                } else if (cmd.startsWith("method")) {
                    /*
                     * Use non default REST method for this operation
                     */
                    method = cmd.substring(cmd.indexOf("=") + 1,
                                           cmd.length());
                }
            }
        }


        /**
         * Get Http REST path to be used
         * @return
         */
        public String path() {
           return path;
        }

        /**
         * Get Http REST method to be used
         * @return
         */
        public String method() {
            return method;
        }

        /**
         * Get meta data for certain node
         */
        private String getMetaData(NavuNode node) {
            List<MaapiSchemas.CSNode> chlist =
                node.getInfo().getCSNode().getChildren();

            if (chlist != null) {
                Iterator<MaapiSchemas.CSNode> it = chlist.iterator();
                while (it.hasNext()) {
                    MaapiSchemas.CSNode c = it.next();
                    if (c.getTag().equals("NED-META")) {
                        return c.getDefval().toString();
                    }
                }
            }
            return null;
        }


        /**
         * Recursively build a REST path out of the node schema.
         * Replace key names with UUID where applicable.
         *
         * @param node     - Current node in the schema
         * @param initial  - Initial node in the schema
         *
         * @return a REST PATH
         *
         * @throws NavuException
         */
        private String doPath(NavuNode node, NavuNode initial)
            throws NavuException {

            if (node.getKeyPath().equals(ncsPrefix + "config")) {
                return "/";
            }

            String path = doPath(node.getParent(), initial);

            if (node instanceof NavuList) {
                path += node.getName().replace(PREFIX,"") + "/";
            } else if (node instanceof NavuListEntry) {

                if (node != initial) {
                    NavuListEntry entry = (NavuListEntry)node;
                    path += entry.getKey().elementAt(0).toString() + "/";
                }
            }
            path = path.replace("devname:", "");
            return path;
        }
    }


    /**
     * Generates a list of key tags in the schem starting at a specified node.
     *
     */
    private class KeyTags {
        private List<String> keyTags = null;

        KeyTags(NavuNode node) {
            keyTags = new ArrayList<String>();
            findKeyTags(node.getInfo().getCSNode());
        }

        private void findKeyTags(CSNode node) {
            String tag;

            if (node.isContainer() || node.isList()) {
                for (CSNode child : node.getChildren()) {
                    findKeyTags(child);
                }
            }

            if (node.isList()) {
                tag = node.getKey(0).getTag();
                if (!keyTags.contains(tag))
                    keyTags.add(tag);
            }
        }

        public List<String> get() {
            return keyTags;
        }
    }


    /**
     * Simple utility to deal with ConfXMLParam lists containing sublevels.
     * The config at each sublevel will be handled with a separate REST call.
     *
     * This utility is used for flattening a ConfXMLParam list, i.e delete
     * all sublevels.
     *
     */
    private static class RestDeviceXMLParam {

        private static void findElementsToDelete(List<ConfXMLParam> src,
                                          List<ConfXMLParam> del,
                                          int i) {

            for (; i < src.size(); i++) {
                if (src.get(i) instanceof ConfXMLParamStart) {
                    int hash = src.get(i).getTagHash();

                    for (; i < src.size(); i++) {
                        ConfXMLParam current = src.get(i);
                        del.add(current);
                        if ((current instanceof ConfXMLParamStop) &&
                            (current.getTagHash() == hash))
                            break;
                    }
                    if (i < src.size()) {
                        findElementsToDelete(src, del, i+1);
                    }
                    break;
                }
            }
        }

        public static void flatten (List<ConfXMLParam> list) {
            List<ConfXMLParam> deleteList = new ArrayList<ConfXMLParam>();
            findElementsToDelete(list.subList(1, list.size() - 1),
                                 deleteList, 0);
            list.removeAll(deleteList);
        }
    }


    /**
     * NED Constructors
     */
    public dnNedGeneric(){
        logger.debug("dnNedGeneric constructor");
    }


    @SuppressWarnings({ "deprecation", "nls" })
	public dnNedGeneric(String deviceId,
                                 InetAddress ip,
                                 int port,
                                 String luser,
                                 boolean trace,
                                 int connectTimeout,
                                 int readTimeout,
                                 int writeTimeout,
                                 NedMux mux,
                                 NedWorker worker) {
        this.deviceId = deviceId;
        this.ip = ip;
        this.port = port;
        this.luser = luser;
        this.trace = trace;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.writeTimeout = writeTimeout;
        this.ncsPrefix = "/ncs:devices/device{"+deviceId+"}/";
    	this.user = worker.getRemoteUser();
		this.password = worker.getPassword();
	

        try {
            ResourceManager.registerResources(this);
        } catch (Exception e) {
            logger.error("Error injecting Resources", e);
        }

        this.capas[0] = new NedCapability("", IDENTITY, MODULE, "", DATE, "");
        this.capas[1] = new NedCapability("urn:ietf:params:netconf:"
            + "capability:with-defaults:1.0?"
            + "basic-mode=report-all",
            "urn:ietf:params:netconf:capability:with-defaults:1.0",
            "",
            "",
            "",
            "");

        // TODO: Uncomment below if you need stats
        
                 this.stats_capas[0] = new NedCapability("",
                                                         "http://com/tailf/packages/ned/devname/stats",
                                                         "devname-stats",
                                                         "",
                                                         DATE,
                                                         "");

        logger.info("NED VERSION: "
                   + MODULE
                   + " "
                   + VERSION
                   + " "
                   + DATE
                   + " "
                   + deviceId);

        logger.debug("setConnectionData -->");
        setConnectionData(capas,   stats_capas, WANT_REVERSE, TRANS_ID_MODE);
        logger.debug("<-- setConnectionData");

        try {
           logger.debug("maapi read ned-settings -->");
            maapi.setUserSession(1);
            int th = maapi.startTrans(Conf.DB_RUNNING, Conf.MODE_READ);

            ConfValue val;
            ConfPath p = new ConfPath(ncsPrefix
                                      + "ncs:ned-settings/"
                                      + "devname-connection/");
            /*
             * Fetch api-key
             */
            val = maapi.safeGetElem(th, p.copyAppend("api-key"));

            if (val != null) {
                apiKey = val.toString();
            }

            /*
             * Fetch optional relative URL
             */
            val = maapi.safeGetElem(th, p.copyAppend("api-base-url"));

            if (val != null) {
                baseUrl = val.toString();
            }

            /*
             * Fetch optional SSL settings
             */
            p = p.append("ssl/");

            ConfBinary bytes = (ConfBinary)maapi.
                safeGetElem(th, p.copyAppend("certificate"));

            if (bytes != null) {
                cert = bytes.bytesValue();
            }

            acceptAny = maapi.exists(th, p.copyAppend("accept-any"));

            if (cert != null || acceptAny) {
                useSSL = true;
            }

            if (cert != null) {
                logger.debug("Using SSL certificate: " + cert.toString());
            }

            logger.debug("<-- maapi read ned-settings");

            /*
             * Create a REST connection
             */
            logger.debug("CONNECTING");

            connection = new RESTConnection(deviceId, ip, port,
                 apiKey, baseUrl, connectTimeout, readTimeout,
                 writeTimeout, useSSL, acceptAny, trace, cert, worker);

            logger.debug("CONNECTING ==> OK");

            transformer = new JsonTransformer(deviceId, trace);

            //            cdbOper = cdb.startSession(CdbDBType.CDB_OPERATIONAL);

            getDeviceInfo(worker);

            logger.debug("CONNECTING ==> OK");
        } catch (Exception e) {
            worker.error(NedCmd.CONNECT_GENERIC, "Connect error: " + e.getMessage());
        }
    }


    /**
     * Utility for extracting information about the device we are
     * currently connected to. This is not supported by the so
     * the information is currently hard coded.
     *
     * @param worker
     */
    private void getDeviceInfo (NedWorker worker) {

        try {
            /*
             * On NSO 4.0 and later, do register device model and
             * os version.
             */
            if (Conf.LIBVSN >= 0x6000000) {
                ConfXMLParam[] platformData =
                    new ConfXMLParam[] {
                        new ConfXMLParamStart("ncs", "platform"),
                        new ConfXMLParamValue("ncs", "name",
                                              new ConfBuf("REST device")),
                        new ConfXMLParamValue("ncs", "version",
                                              new ConfBuf("unknown")),
                        new ConfXMLParamValue("ncs", "model",
                                              new ConfBuf("unknown")),
                        new ConfXMLParamStop("ncs", "platform")
                };

                Method method = this.getClass().
                    getMethod("setPlatformData",
                              new Class[]{ConfXMLParam[].class});
                method.invoke(this, new Object[]{platformData});
            }
        } catch (Exception e) {
            logger.error("Failed to install platform information :: " +
                e.getMessage());
        }
    }


    /**
     * Returns device ID
     * @return
     */
    @Override
    public String device_id() {
        return deviceId;
    }


    /**
     * Returns 'generic'
     * @return
     */
    @Override
    public String type() {
        return TYPE;
    }


    /**
     * Returns the YANG models covered by this NED
     * @return
     */
    @Override
    public String [] modules() {
        return new String[] { "tailf-ned-" + MODULE };
    }


    /**
     * Return the NED identity
     * @return
     */
    @Override
    public String identity() {
        return MODULE + "-id:" + MODULE;
    }


    /**
     * NED prepare hook.
     * Responsible for applying the config diff on the device, by sending
     * the appropriate REST messages.
     *
     * @param worker - NED worker thread
     * @param ops    - Config operations
     * @throws NedException
     * @throws IOException
     */
    @Override
    public void prepare(NedWorker worker, NedEditOp[] ops)
            throws NedException, IOException {

        logger.debug("PREPARE <==");
        try {
            edit(worker, ops, null, worker.getToTransactionId());
            worker.prepareResponse();
            logger.debug("PREPARE ==> OK");
        } catch (Exception e) {
            logger.error("Error in prepare", e);
            e.printStackTrace();
            worker.error(NedCmd.PREPARE_GENERIC,
                         "Prepare error: " + e.getMessage());
        }
    }


    /**
     * NED dry-run prepare hook.
     * Creates the REST messages to apply the config diff without actually
     * sending them to the device.
     * @param worker   - worker thread
     * @param ops      - Config operations
     * @throws NedException
     */
    @Override
    public void prepareDry(NedWorker worker, NedEditOp[] ops)
            throws NedException {
        StringBuilder result = new StringBuilder();

        logger.debug("PREPARE <==");
        try {
            edit(worker, ops, result, worker.getToTransactionId());
            worker.prepareDryResponse(result.toString());
            logger.debug("PREPARE ==> OK");
        } catch (Exception e) {
            String msg = e.getMessage();

            if (msg != null && msg.length() > 254) {
                msg = msg.substring(0, 254);
            }
            worker.error(NedCmd.PREPARE_GENERIC, "Prepare dry error: " + msg);
        }
    }


    /**
     * NED commit hook
     * @param worker
     * @param timeout
     * @throws NedException
     * @throws IOException
     */
    @Override
    public void commit(NedWorker worker, int timeout)
            throws NedException, IOException {
        logger.debug("COMMIT <==");
        worker.commitResponse();
        logger.debug("COMMIT ==> OK");
    }


    /**
     * NED abort hook
     * @param worker
     * @param ops
     * @throws NedException
     * @throws IOException
     */
    @Override
    public void abort(NedWorker worker , NedEditOp[] ops)
            throws NedException, IOException {
        logger.debug("ABORT <==");
        try {
            //edit(worker, ops, worker.getToTransactionId());
            worker.abortResponse();
            logger.debug("ABORT ==> OK");
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Could not abort towards the device");
            worker.error(NedCmd.PREPARE_GENERIC, "Abort error: " + e.getMessage());
        }
    }


    /**
     * NED revert hook
     * @param worker
     * @param ops
     * @throws NedException
     * @throws IOException
     */
    @Override
    public void revert(NedWorker worker , NedEditOp[] ops)
            throws NedException, IOException {
        logger.debug("REVERT <==");
        try {
            edit(worker, ops, null, worker.getToTransactionId());
            worker.revertResponse();
            logger.debug("REVERT ==> OK");
        } catch(Exception e) {
            logger.error("Could not revert towards the device");
            worker.error(NedCmd.REVERT_GENERIC,
                         "Revert error: "+ e.getMessage());
        }
    }


    /**
     * Create a NavuNode object out of the config path in a NedEditOp entry.
     * @param op - The NedEditOp entry
     * @param th - Transaction handle
     *
     * @return a NavuNode
     * @throws Exception
     */
    private NavuNode getNode(NedEditOp op, int th) throws Exception {

        NavuContainer root = new NavuContainer(new NavuContext(maapi,th));
        NavuNode node = root.getNavuNode(new ConfPath(this.ncsPrefix
                                                      + "config/"
                                                      + op.getPath()));

        return node;
    }


    /**
     * Applies the config
     * @param worker     - worker thread
     * @param ops        - Array of NedEditOps
     * @param dryRun     - StringBuilder. != null if called in dry-run mode.
     * @param th         - transaction handle
     *
     * @throws Exception
     */
    private void edit(NedWorker worker, NedEditOp[] ops,
                      StringBuilder dryRun, int th)
            throws Exception  {
        maapi.attach(worker.getFromTransactionId(), 0, worker.getUsid());
        maapi.attach(worker.getToTransactionId(), 0, worker.getUsid());
        try {
            NavuNode previous = null;
            NavuNode current = null;

            for (NedEditOp op: ops) {

                switch (op.getOperation()) {
                case NedEditOp.CREATED:
                    current = getNode(op, worker.getToTransactionId());
                    create(worker, current, dryRun);
                    break;
                case NedEditOp.DELETED:
                    current = getNode(op, worker.getFromTransactionId());
                    delete(worker, current, dryRun);
                    break;
                case NedEditOp.MOVED:
                case NedEditOp.VALUE_SET:
                case NedEditOp.DEFAULT_SET:
                    current = getNode(op, worker.getToTransactionId());
                    if (!current.getParent().equals(previous)) {
                        update(worker, current, dryRun);
                    }
                    break;
                }
                previous = current;
            }
        } finally {
            maapi.detach(worker.getFromTransactionId());
            maapi.detach(worker.getToTransactionId());
        }
    }


    /**
     * Config create handler
     * @param worker     - NED worker thread
     * @param node       - NavuNode to operate on.
     * @param dryRun     - != null if in dry-run mode.
     *
     * @throws Exception
     */
    private void create(NedWorker worker, NavuNode node, StringBuilder dryRun)
        throws Exception  {
        List<ConfXMLParam> list = node.encodeXML();

        RestDeviceXMLParam.flatten(list);

        ConfXMLParam[] params = new ConfXMLParam[list.size()-2];
        list.subList(1,list.size()-1).toArray(params);
        params = node.getValues(params);

        String json = transformer.XmlToJson(worker,
                                            ConfXMLParam.toXML(params));

        if (json != null) {
        	json = json.replace("\"atlassian-", "\"");
            RESTHttp http = new RESTHttp(node, false, "CREATE");

            if (dryRun != null) {
                dryRun.append("POST " + "/rest/api/1.0" + http.path() +"\n"+json+"\n");
                return;
            }

            json = connection.post(worker, "/rest/api/1.0" + http.path(), json, user, password);
            
            logger.debug("REST DEVICE CREATE RESPONSE ::" + json);
        }
    }



    /**
     * Config update handler
     * @param worker     - NED worker thread
     * @param node       - NavuNode to operate on.
     * @param dryRun     - != null if in dry-run mode.
     *
     * @throws Exception
     */
    private void update(NedWorker worker, NavuNode node, StringBuilder dryRun)
        throws Exception  {
        NavuNode parent = node.getParent();
        List<ConfXMLParam> list = parent.encodeXML();

        RestDeviceXMLParam.flatten(list);

        ConfXMLParam[] params = new ConfXMLParam[list.size()-2];
        list.subList(1,list.size()-1).toArray(params);
        params = parent.getValues(params);

        String json = transformer.XmlToJson(worker,
                                            ConfXMLParam.toXML(params));

        if (json != null) {
        	json = json.replace("\"atlassian-", "\"");
            RESTHttp http = new RESTHttp(node, false, "UPDATE");

            if (dryRun != null) {
                dryRun.append("PUT " + "/rest/api/1.0" + http.path() +"\n"+json+"\n");
                return;
            }

            json = connection.put(worker,"/rest/api/1.0" + http.path(), json, user, password);

            logger.debug("REST DEVICE UPDATE RESPONSE ::" + json);
        }
    }



    /**
     * Config delete handler
     * @param worker     - NED worker thread
     * @param node       - NavuNode to operate on.
     * @param dryRun     - != null if in dry-run mode.
     *
     * @throws Exception
     */
    private void delete(NedWorker worker ,NavuNode node, StringBuilder dryRun)
        throws Exception {

        RESTHttp http = new RESTHttp(node, true, "DELETE");

        String method = http.method() == "default" ? "DELETE" : http.method();

        if (dryRun != null) {
            dryRun.append(method + " " + "/rest/api/1.0" + http.path() + "\n");
            return;
        }

        String json;
        if (method.equals("POST")) {
            json = connection.post(worker, "/rest/api/1.0" + http.path(), null, user, password);
        } else if (method.equals("PUT")) {
            json = connection.put(worker, "/rest/api/1.0" + http.path(), null, user, password);
        }
        else {
            json = connection.delete(worker, "/rest/api/1.0" + http.path(), user, password);
        }

        logger.debug("REST DEVICE DELETE RESPONSE :: " + json);
    }
    /**
     * NED persist hook
     * @param worker
     * @throws NedException
     * @throws IOException
     */
    @Override
    public void persist(NedWorker worker)
            throws NedException, IOException {
        logger.debug("PERSIST <==");
        worker.persistResponse();
    }


    /**
     * NED close hook
     * @param worker
     * @throws NedException
     * @throws IOException
     */
    @Override
    public void close(NedWorker worker)
            throws NedException, IOException {
        close();
    }


    /**
     * NED close hook
     */
    @Override
    public void close() {
        logger.debug("CLOSE <==");
        /*
         * Clear up CDB session, context and the socket.
         */
// TODO: If cdb-oper-data is used, include this
//      try {
//          cdbOper.endSession();
//      } catch (IOException e) {
//          logger.error("Error closing cdb socket :: IO :: "
//                          + e.getMessage());
//      } catch (ConfException e) {
//          logger.error("Error closing cdb socket :: Conf :: "
//                          + e.getMessage());
//         }

        /*
         * Close REST connection.
         */
        try {
            connection.close();
        } catch (Exception e) {
            logger.error("Error closing REST connection :: " + e.getMessage());
        }

        try {
            ResourceManager.unregisterResources(this);
        } catch (IllegalAccessException e) {
            logger.error("Error unRegistering Resources", e);
        }

        logger.debug("CLOSE ==> OK");
    }


//    /**
//     * Recursively load config from the device to cdb and cdb-oper
//     * @param worker    - NED worker thread
//     * @param th        - transaction handler
//     * @param node      - current root node
//     * @throws Exception
//     */
//    @SuppressWarnings("deprecation")
//    private void getConfig(NedWorker worker, int th, NavuNode node)
//        throws Exception {
//        String nodeName = node.getName().replace(PREFIX, "");
//        ConfXMLParam[] params;
//        ConfPath cp;
//        String path;
//        String json;
//        String xml;
//
//        if (node instanceof NavuLeaf)
//            return;
//
//        try {
//            RESTHttp http = new RESTHttp(node, true, "GET");
//            logger.debug("GETTING :: "
//                        + node.getKeyPath()
//                        + " :: "
//                        + http.path());
//
//            json = connection.get(worker, http.path());
//
//            if (json == null)
//                return;
//
//            KeyTags keys = new KeyTags(node);
//            xml = transformer.JsonToXml(worker, nodeName, json, keys.get());
//
//            if (xml == null)
//                return;
//            /*
//             * Load the entire xml config into ncs
//             */
//            path = node.getKeyPath();
//            if (node instanceof NavuList) {
//                path = path.substring(0, path.lastIndexOf(node.getName()));
//            }
//            cp = new ConfPath(path);
//            params = ConfXMLParam.toXMLParams(xml, cp);
//            maapi.setValues(th, params, cp);
//
//            /*
//             * Get next level in the tree
//             */
//            for (NavuNode child : node.children()) {
//                getConfig(worker, th, child);
//            }
//        }
//        catch (Exception e) {
//            throw new NedException(e.getMessage());
//        }
//    }


    /**
     * NED show hook. Loads the config into CDB and CDB-OPER
     * @param worker
     * @param th
     * @throws NedException
     * @throws IOException
     */
    @Override
    public void show(NedWorker worker, int th)
            throws NedException, IOException {
    	logger.debug("SHOW");
        String configXML = "";
    	if (maapi == null)
			try {
				maapi = ResourceManager.getMaapiResource(this, Scope.INSTANCE);
			} catch (IllegalAccessException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (ConfException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
		try {
			maapi.attach(th, 0, worker.getUsid());
		} catch (ConfException e1) {
			e1.printStackTrace();
		}        

		try {
        	String loadToCDBJson= "";
        	
        	String projectName = null;
			String projectKey = null;
			String projectDescription = null;

			JSONObject projectsAll= new JSONObject(connection.get(worker, "/rest/api/1.0/projects/", user, password));
			JSONArray projects = projectsAll.getJSONArray("values");
			JSONObject reposAll = null;
			JSONArray repos = null;
			
			JSONArray loadAllProjects = new JSONArray();
			for (int i = 0; i < projects.length(); i++) {
				projectName = projects.getJSONObject(i).getString("name");
				projectKey = projects.getJSONObject(i).getString("key");
				reposAll = new JSONObject(connection.get(worker, "/rest/api/1.0/projects/"+projectKey+"/repos", user, password));
				repos = reposAll.getJSONArray("values");
				try {
					projectDescription = projects.getJSONObject(i).getString("description");
					loadToCDBJson = "{\"name\" : \""+projectName+"\", " + 
							"\"key\" : \""+projectKey+"\", "+ 
							"\"description\" : \""+projectDescription+"\", "+ 
							"\"repos\" : "+ repos+"}";
				} catch (JSONException je) {
					loadToCDBJson = "{\"name\" : \""+projectName+"\", " + 
							"\"key\" : \""+projectKey+"\", "+ 
							"\"repos\" : "+ repos+"}";
				}
				
				
				loadAllProjects.put(new JSONObject(loadToCDBJson));	
				
		    	
			}
			
			loadToCDBJson = "{\"projects\" : "+loadAllProjects+"}";			
			configXML = JsonXmlUtils.convertJsonToXML(loadToCDBJson, "config");
	    	configXML = this.moveKeyLeafTop(configXML, "projects", "key");
	    	configXML = this.moveKeyLeafTop(configXML, "repos", "name");
			configXML = this.modifyToNcsFormat(configXML, "projects", "config");
			String res = "<devices xmlns=\"http://tail-f.com/ns/ncs\">"
	                + "<device>" + "<name>" + deviceId + "</name>"
	                + configXML + "</device></devices>";
			
	        maapi.loadConfigCmds(th, cmdflagsConfig, res, "");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        worker.showGenericResponse();
        logger.debug("SHOW ==> OK");    }


    /**
     * NED isAlive hook.
     * @return true always
     */
    @Override
    public boolean isAlive() {
        return true;
    }


    /**
     * NED reconnect hook
     * @param worker
     */
    @Override
    public void reconnect(NedWorker worker) {
        // all capas and transmode already set in constructor
        // nothing needs to be done
    }


    /**
     * NED isConnection hook
     * @param deviceId
     * @param ip
     * @param port
     * @param luser
     * @param trace
     * @param connectTimeout
     * @param readTimeout
     * @param writeTimeout
     * @return
     */
    @Override
    public boolean isConnection(String deviceId,
            InetAddress ip,
            int port,
            String luser,
            boolean trace,
            int connectTimeout, // msecs
            int readTimeout,    // msecs
            int writeTimeout) { // msecs
        return ((this.deviceId.equals(deviceId)) &&
                (this.ip.equals(ip)) &&
                (this.port == port) &&
                (this.luser.equals(luser)) &&
                (this.trace == trace) &&
                (this.connectTimeout == connectTimeout) &&
                (this.readTimeout == readTimeout) &&
                (this.writeTimeout == writeTimeout));
    }


    /**
     * NED command hook
     * @param worker
     * @param cmdname
     * @param p
     * @throws NedException
     * @throws IOException
     */
    @Override
    public void command(NedWorker worker, String cmdname, ConfXMLParam[] p)
            throws NedException, IOException {
        logger.info("Device ID:" + deviceId);
    }

    /**
     * Establish a new connection to a device and send response to
     * NCS with information about the device.
     *
     * @param deviceId name of devide
     * @param ip address to connect to device
     * @param port port to connect to
     * @param proto ssh or telnet
     * @param luser name of local NCS user initiating this connection
     * @param trace indicates if trace messages should be generated or not
     * @param connectTimeout in milliseconds
     * @param readTimeout in milliseconds
     * @param writeTimeout in milliseconds
     * @return the connection instance
     **/
    @Override
    public NedGenericBase newConnection(String deviceId,
            InetAddress ip,
            int port,
            String luser,
            boolean trace,
            int connectTimeout, // msecs
            int readTimeout,    // msecs
            int writeTimeout,   // msecs
            NedMux mux,
            NedWorker worker ) {
        logger.debug("newConnection() <==");
        dnNedGeneric ned = new dnNedGeneric(deviceId,
                                  ip,
                                  port,
                                  luser,
                                  trace,
                                  connectTimeout,
                                  readTimeout,
                                  writeTimeout,
                                  mux,
                                  worker);

        logger.debug("NED invoking newConnection() ==> OK");

        return ned;
    }


    @Override
    public void getTransId(NedWorker w) throws NedException, IOException {
        w.error(NedCmd.GET_TRANS_ID, "getTransId", "not supported");
    }


    @SuppressWarnings("deprecation")
    @Override
    public void showStats(NedWorker worker, int tHandle, ConfPath path)
        throws Exception {
        try {
            if (maapi == null)
                maapi = ResourceManager.getMaapiResource(this, Scope.INSTANCE);
            logger.info( this.toString()  + " Attaching to Maapi " + maapi +
                    " for " + path);
            maapi.attach(tHandle, 0, worker.getUsid());
            maapi.detach(tHandle);
            NedTTL ttl = new NedTTL(path,0);
            worker.showStatsResponse(new NedTTL[]{ttl});
        }
        catch (Exception e) {
            throw new NedException("", e);
        }
    }


    @SuppressWarnings("deprecation")
    @Override
    public void showStatsList(NedWorker worker, int tHandle, ConfPath path)
            throws Exception {
        try {
            if (maapi == null)
                maapi = ResourceManager.getMaapiResource(this, Scope.INSTANCE);

            logger.info( this.toString()  + " Attaching2 to Maapi " + maapi +
                    " for " + path);
            maapi.attach(tHandle, 0, worker.getUsid());
            maapi.detach(tHandle);
            worker.showStatsListResponse(0, null);
        }
        catch (Exception e) {
            throw new NedException("", e);
        }
    }
    
    /**
	 * This method moves given element to top. Some XML data return from the
	 * device does not have key element as a first child for a list. To map XML
	 * data in CDB using mapi, key element should to be first child for a list.
	 *
	 * @param data
	 *            XML data from device
	 * @param element
	 *            list element name.
	 * @param key
	 *            key list key name.
	 * @return returns key element changed XML data.
	 * @throws Exception
	 */
	private String moveKeyLeafTop(String data, String element, String key) throws Exception {

		String config = null;
		Document docConfig = JsonXmlUtils.stringToDocument(data);
		NodeList list = docConfig.getElementsByTagName(element);
		// LIST KEY NAME according to Ynag modell
		for (int i = 0; i < list.getLength(); i++) {
			Element parent = (Element) list.item(i);
			Node firstChild = parent.getFirstChild();
			if (!firstChild.getNodeName().equals(key)) {
				NodeList keyElements = parent.getElementsByTagName(key);

				for (int j = 0; j < keyElements.getLength(); j++) {
					Element keyElement = (Element) keyElements.item(j);
					if (keyElement != null && keyElement.getParentNode().getNodeName().equals(element)) {
						Element cloneKey = (Element) keyElement.cloneNode(true);
						parent.insertBefore(cloneKey, firstChild);
						parent.removeChild(keyElement);
					}
				}
			}
		}
		config = JsonXmlUtils.documentToString(docConfig).replaceAll("(?m)^[ \t]*\r?\n", "");
		config = JsonXmlUtils.formatXMLString(config);
		return config;
	}

	/**
	 * Adapts the XML to NCS format
	 *
	 * @param data
	 *            the unformated XML
	 * @param module
	 *            the name of the object
	 * @param rootTag
	 *            the rootTag
	 * @return the formatted XML
	 * @throws Exception
	 */
	private String modifyToNcsFormat(String data, String module, String rootTag) throws Exception {
		data = data.replaceAll("<" + module + ">", "<" + module + " xmlns:" + tailfdnNedGeneric.prefix
				+ "=\"" + tailfdnNedGeneric.uri + "\">");
		data = data.replaceAll("<", "<" + tailfdnNedGeneric.prefix + ":");
		data = data.replaceAll("<" + tailfdnNedGeneric.prefix + ":/",
				"</" + tailfdnNedGeneric.prefix + ":");
		data = data.replaceAll("<" + tailfdnNedGeneric.prefix + ":" + rootTag + ">",
				"<" + rootTag + ">");

		data = data.replaceAll("</" + tailfdnNedGeneric.prefix + ":" + rootTag + ">",
				"</" + rootTag + ">");
		data = data.replaceAll("<" + tailfdnNedGeneric.prefix + ":" + rootTag + "/>",
				"<" + rootTag + "/>");
		data = data.replaceAll("<" + tailfdnNedGeneric.prefix + ":\\?xml", "<?xml");
		return data;
	}
}
