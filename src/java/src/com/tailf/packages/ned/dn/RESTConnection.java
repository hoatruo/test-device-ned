package com.tailf.packages.ned.dn;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpEntity;
import org.apache.http.HttpMessage;
import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

import com.tailf.ned.NedWorker;

import java.net.InetAddress;
import javax.xml.bind.DatatypeConverter;

import org.apache.http.Header;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;


/**
 * Implements an abstration for REST-ful communication towards a device
 *
 */
public class RESTConnection {
    private Logger log;
    private CloseableHttpClient httpClient;
    private String proto;
    private InetAddress ip;
    private String apiKey;
    private int port;
    private String urlBase;
    private String deviceId;
    private boolean trace;
    private int readTimeout;
    private int writeTimeout;

    private static final String DEFAULT_CONTENT_TYPE = "application/json";

    /**
     * Constructors
     */
    public RESTConnection() {
    }


    public RESTConnection(String deviceId,
                          InetAddress ip,
                          int port,
                          String apiKey,
                          String urlBase,
                          int connectTimeout,
                          int readTimeout,
                          int writeTimeout,
                          boolean useSSL,
                          boolean acceptAny,
                          boolean trace,
                          byte[] cert,
                          NedWorker worker) throws Exception {

        this.log = Logger.getLogger(RESTConnection.class);
        this.trace = trace;
        this.deviceId = deviceId;
        this.ip = ip;
        this.port = port;
        this.apiKey = apiKey;
        this.urlBase = urlBase;
        this.readTimeout = readTimeout;
        this.writeTimeout = writeTimeout;

        log.debug("REST CONNECTION ==>");
        worker.setTimeout(connectTimeout);

        if (useSSL) {
            this.proto = "https";
            doConnect(cert, acceptAny);
        } else {
            this.proto = "http";
            doConnect(null, false);
        }

        log.debug("REST CONNECTION OK");
    }


    /**
     * Setup the http client
     * @param cert   - certificate to use for https
     * @param unsafe - if true, accept any
     * @throws Exception
     */
    private void doConnect(byte[] cert, boolean unsafe) throws Exception {
		PlainConnectionSocketFactory psf = PlainConnectionSocketFactory.getSocketFactory();
		SSLConnectionSocketFactory ssf;
		if (unsafe) {
			ssf = new SSLConnectionSocketFactory(getUnsafeSSLContext());
		} else if (cert != null) {
			ssf = new SSLConnectionSocketFactory(getSSLContext(cert));
		} else {
			ssf = SSLConnectionSocketFactory.getSocketFactory();
		}

		HttpClientBuilder builder = HttpClientBuilder.create();
		builder.setSSLSocketFactory(ssf);

		RegistryBuilder<ConnectionSocketFactory> regBuilder = RegistryBuilder.create();
		regBuilder.register("http", psf);
		regBuilder.register("https", ssf);
		Registry<ConnectionSocketFactory> reg = regBuilder.build();

		HttpClientConnectionManager ccm = new PoolingHttpClientConnectionManager(reg);
		builder.setConnectionManager(ccm);

		httpClient = builder.build();
	
//        PlainSocketFactory psf = PlainSocketFactory.getSocketFactory();
//        SSLSocketFactory ssf;
//        if (unsafe) {
//            ssf = new SSLSocketFactory(getUnsafeSSLContext(),
//                                       SSLSocketFactory.
//                                       ALLOW_ALL_HOSTNAME_VERIFIER);
//        } else if (cert != null) {
//            ssf = new SSLSocketFactory(getSSLContext(cert),
//                                       SSLSocketFactory.
//                                       ALLOW_ALL_HOSTNAME_VERIFIER);
//        } else {
//            ssf = SSLSocketFactory.getSocketFactory();
//        }
//
//        Scheme httpscheme = new Scheme("http", 80, psf);
//        Scheme httpsscheme = new Scheme("https", 443, ssf);
//
//        SchemeRegistry reg = new SchemeRegistry();
//        reg.register(httpscheme);
//        reg.register(httpsscheme);
//
//        ClientConnectionManager ccm = new BasicClientConnectionManager(reg);
//        httpClient = new DefaultHttpClient(ccm);
//
//        /*
//         * If you need custom redirects, this is how it can be handled
//         * (see NED cisco-meraki for an example how to use this)
//         *
//         * httpClient.setRedirectStrategy(new MerakiRedirectStrategy());
//         */
    }


    /**
     * Creates the ssl context used for the https session.
     * @param certBytes
     * @return
     */
    private static SSLContext getSSLContext(byte[] certBytes) {
        try {
            CertificateFactory factory =
                CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory
                .generateCertificate(new ByteArrayInputStream(certBytes));

            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(null);
            keystore.setCertificateEntry("NED-client-cert", cert);

            TrustManagerFactory tmf =
                TrustManagerFactory.getInstance("SunX509");
            tmf.init(keystore);
            TrustManager[] tm = tmf.getTrustManagers();

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tm , null);

            return context;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    /**
     *
     * @return
     */
    private static SSLContext getUnsafeSSLContext() {
        try {
            TrustManager[] tm = { new UnsafeTrustManager() };
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tm , null);

            return context;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    private static class UnsafeTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] a, String b) {}

        @Override
        public void checkServerTrusted(X509Certificate[] a, String b) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }


    /**
     * Trace print the contents of the REST messages.
     * @param worker  - the ned worker context
     * @param msg     - the http message
     * @throws IOException
     * @throws IllegalStateException
     */
    private void traceMessage(NedWorker worker, HttpMessage msg, String result)
        throws IllegalStateException, IOException {
        Header[] headers = msg.getAllHeaders();
        String direction = "out";

        if (worker == null) {
            return;
        }

        if (msg instanceof HttpEntityEnclosingRequestBase) {
            direction = "out";
        } else if (msg instanceof HttpResponse) {
            direction = "in";
        }

        try {
            worker.trace(msg.toString(), direction, deviceId);
            for (Header h : headers) {
                worker.trace(h.getName()
                             + " : "
                             + h.getValue()
                             + " ",
                             direction,
                             deviceId);
            }

            if (result != null) {
                worker.trace(result, direction, deviceId);
            }
        }
        catch (ParseException exc) {
            log.error("traceMessage :: Failed to parse ::" + exc.getMessage());
        }
    }


    /**
     * Generic send routing for any type of HTTP message.
     *
     * @param worker - current worker thread
     * @param msg    - the HTTP message
     *
     * @return a reply
     * @throws Exception
     */
    private String send(NedWorker worker, HttpRequestBase msg, String user, String password)
        throws Exception {

    	byte[] auth = (user + ":" + password).getBytes("UTF-8");
        String encoded = DatatypeConverter.printBase64Binary(auth);
        
        msg.addHeader("Authorization", "Basic " + encoded);
        msg.addHeader("Content-type", DEFAULT_CONTENT_TYPE);
        msg.addHeader("Accept", DEFAULT_CONTENT_TYPE);
        
        HttpResponse response = this.httpClient.execute(msg);
        StatusLine statusLine = response.getStatusLine();

        String result = null;
        if (response.getEntity() != null) {
            result = EntityUtils.toString(response.getEntity());
        }

        if (trace) {
            traceMessage(worker, response, result);
        }

        if (statusLine.getStatusCode() >= 300) {
            String reason;

            /*
             * TODO: Check how device responds to errors, handle here.
             */
            if ((statusLine.getStatusCode() == 400 ||
                statusLine.getStatusCode() == 403 ) && result.length() > 0) {
                /*
                 * If the device gives a reason in the result for certain codes,
                 * we can handle it here.
                 */
                reason = result.toString();
            }
            else {
                reason = statusLine.getReasonPhrase();
            }

            throw new HttpResponseException(statusLine.getStatusCode(), reason);
        }

        return result;
    }


    /**
     * Implements a HTTP GET call
     *
     * @param worker - current worker thread
     * @param path   - URL path
     *
     * @return JSON formatted string with config
     *
     * @throws Exception
     */
    public String get(NedWorker worker, String path, String user, String password) throws Exception {

        URI uri = new URI(proto, null, ip.getHostAddress(),
                          port, urlBase + path, null, null);
                
        HttpGet get = new HttpGet(uri);
        String buf;

        worker.setTimeout(readTimeout);

        if (trace) {
            traceMessage(worker, get, "");
        }

        try {
            buf = send(worker, get, user, password);
        } catch (HttpResponseException e) {
            if (e.getStatusCode() == 404 || e.getStatusCode() == 400) {
                return null;
            }
            else {
                throw new Exception(e.getMessage());
            }
        }

        return buf;
    }


    /**
     * Implements a HTTP POST call
     *
     * @param worker - current worker thread
     * @param path   - URL path
     * @param json    - JSON formatted message
     *
     * @return A JSON formatted reply message
     *
     * @throws Exception
     */
    public String post(NedWorker worker, String path, String json, String user, String password)
        throws Exception {
        URI uri = new URI(proto, null, ip.getHostAddress(),
                        port, urlBase + path, null, null);

      HttpPost post = new HttpPost(uri);

      if (json != null) {
          HttpEntity e = new StringEntity(json);
          post.setEntity(e);
      }
      worker.setTimeout(writeTimeout);

      if (trace) {
          traceMessage(worker, post, json);
      }
      String buf = null;
      try {
          buf = send(worker, post, user, password);
      } catch (HttpResponseException e) {
          if (e.getStatusCode() == 404) {
              return null;
          } else if(e.getStatusCode() == 409){
          	log.error("could not send\nerror code: " + e.getStatusCode() + " -> Project key must be unique: " + uri + "\n" + json);
              throw new Exception("could not send\nerror code: " + e.getStatusCode() + " -> Project key must be unique: " + uri + "\n" + json);
          } else {
          	log.error("could not send\nerror code: " + e.getStatusCode() + " -> " + e.getMessage());
              throw new Exception(e.getMessage());
          }
      }

      return buf;
    }


    /**
     * Implements a HTTP REST PUT call
     *
     * @param worker - current worker thread
     * @param path   - URL path
     * @param json    - JSON formatted message
     *
     * @return A JSON formatted reply message
     *
     * @throws Exception
     */
    public String put(NedWorker worker, String path, String json, String user, String password)
        throws Exception {
        URI uri = new URI(proto, null, ip.getHostAddress(),
                        port, urlBase + path, null, null);

      HttpPut put = new HttpPut(uri);


      if (json != null) {
          HttpEntity e = new StringEntity(json);
          put.setEntity(e);
      }

      worker.setTimeout(writeTimeout);

      if (trace) {
          traceMessage(worker, put, json);
      }

      return  send(worker, put, user, password);
    }


    /**
     * Implements a HTTP REST DELETE call
     *
     * @param worker - current worker thread
     * @param path   - URL path
     *
     * @return JSON formatted string with config
     *
     * @throws Exception
     */
    public String delete(NedWorker worker, String path,String user, String password) throws Exception {

        URI uri = new URI(proto, null, ip.getHostAddress(),
                          port, urlBase + path, null, null);
        HttpDelete delete = new HttpDelete(uri);
        String buf;

        worker.setTimeout(writeTimeout);

        if (trace) {
            traceMessage(worker, delete, "");
        }

        try {
            buf = send(worker, delete, user, password);
        } catch (HttpResponseException e) {
            if (e.getStatusCode() == 404) {
                return null;
            } else if(e.getStatusCode() == 409){
            	log.error("could not send\nerror code: " + e.getStatusCode() + " -> Can only delete projects without repos: " + uri);
                throw new Exception("could not send\nerror code: " + e.getStatusCode() + " -> Can only delete projects without repos: " + uri);
            } else {
            	log.error("could not send\nerror code: " + e.getStatusCode() + " -> " + e.getMessage());
                throw new Exception(e.getMessage());
            }
        }

        return buf;
    }


    /**
     * Closes the HTTP connection
     */
    public void close() throws Exception {
        log.debug("REST CLOSE ==>");
        httpClient.close();
        log.debug("REST CLOSE OK");
    }
}

