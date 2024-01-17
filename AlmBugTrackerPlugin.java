/**
(c) Copyright [2015-2018] Micro Focus or one of its affiliates.
 */

package com.fortify.sample.bugtracker.alm;

import com.fortify.pub.bugtracker.plugin.AbstractBatchBugTrackerPlugin;
import com.fortify.pub.bugtracker.plugin.BugTrackerPluginImplementation;
import com.fortify.pub.bugtracker.plugin.InterruptableBugtracker;
import com.fortify.pub.bugtracker.support.Bug;
import com.fortify.pub.bugtracker.support.BugParam;
import com.fortify.pub.bugtracker.support.BugParamChoice;
import com.fortify.pub.bugtracker.support.BugParamText;
import com.fortify.pub.bugtracker.support.BugParamTextArea;
import com.fortify.pub.bugtracker.support.BugSubmission;
import com.fortify.pub.bugtracker.support.BugTrackerAuthenticationException;
import com.fortify.pub.bugtracker.support.BugTrackerConfig;
import com.fortify.pub.bugtracker.support.BugTrackerException;
import com.fortify.pub.bugtracker.support.BugTrackerPluginConstants;
import com.fortify.pub.bugtracker.support.IssueComment;
import com.fortify.pub.bugtracker.support.IssueDetail;
import com.fortify.pub.bugtracker.support.MultiIssueBugSubmission;
import com.fortify.pub.bugtracker.support.UserAuthenticationStore;
import com.fortify.sample.bugtracker.alm.infra.Entity;
import com.fortify.sample.bugtracker.alm.infra.EntityMarshallingUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.bind.JAXBException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * Implementation of SSC bug tracker plugin API for ALM using Apache HTTP Client 4.5.2.
 * HTTP communication has been changed from 17.x SSC version following the guidelines and recommendations from
 * Apache HTTP Client 4.5.x
 *
 * Plugin accepts predefined proxy parameters if they are sent and configured from SSC, and uses a corresponding proxy for http/https requests.
 * If SSC proxy is not configured for plugin, the approach from previous version using system proxy properties is used.
 *
 * The core executive method for satisfying http(s) requests is runQueryInContext(...).
 * The API method processing can consist from one or more http requests and it is essential that all these related
 * requests use dedicated HttpClosableClient and PoolingHttpClientConnectionManager being persistent
 * during every hi-level API method processing, because things like cookies, credentials, timings and connections
 * are saved in these components.
 *
 * A new instance of HttpClosableClient for further processing is returned from authenticate(...) method
 * if ALM authentication is successful and must be used as a client for all other subsequent API method's http requests.
 */
@BugTrackerPluginImplementation
public class AlmBugTrackerPlugin extends AbstractBatchBugTrackerPlugin implements InterruptableBugtracker {

    private static final Log LOG = LogFactory.getLog(AlmBugTrackerPlugin.class);

    private enum ProxyField {
        HTTP_PROXY_HOST("httpProxyHost", "HTTP Proxy Host")
        , HTTP_PROXY_PORT("httpProxyPort", "HTTP Proxy Port")
        , HTTP_PROXY_USERNAME("httpProxyUsername", "HTTP Proxy Username")
        , HTTP_PROXY_PASSWORD("httpProxyPassword", "HTTP Proxy Password")
        , HTTPS_PROXY_HOST("httpsProxyHost", "HTTPS Proxy Host")
        , HTTPS_PROXY_PORT("httpsProxyPort", "HTTPS Proxy Port")
        , HTTPS_PROXY_USERNAME("httpsProxyUsername", "HTTPS Proxy Username")
        , HTTPS_PROXY_PASSWORD("httpsProxyPassword", "HTTPS Proxy Password")
        ;

        final private String fieldName;
        final private String displayLabel;

        String getFieldName() {
            return fieldName;
        }
        String getDisplayLabel() {
            return displayLabel;
        }

        ProxyField(final String fieldName, final String displayLabel) {
            this.fieldName = fieldName;
            this.displayLabel = displayLabel;
        }
    }

    private static final String HTTP_PROTOCOL = "http";
    private static final String HTTPS_PROTOCOL = "https";

    private static final String PROXY_EMPTY_VALUE = null;

    private enum ALMApiVersion {
        VER_11, VER_11_52,
    }

    private static final String STATUS_NEW = "New";
    private static final String STATUS_OPEN = "Open";
    private static final String STATUS_REOPEN = "Reopen";
    private static final String STATUS_CLOSED = "Closed";
    private static final String STATUS_FIXED = "Fixed";
    private static final String STATUS_REJECTED = "Rejected";

    private static final int DEFAULT_HTTP_PORT = 80;
    private static final int DEFAULT_HTTPS_PORT = 443;
    private static final int DEFAULT_TRIM_LENGTH = 255;
    private static final int DEFAULT_DESCRIPTION_TRIM_LENGTH = 10000;
    private static final int DEFAULT_COMMENTS_TRIM_LENGTH = 10000;
    private static final int TRIM_LENGTH_UNLIMITED = -1;
    private static final String ELLIPSIS = "...";
    private static final int ELLIPSIS_LEN = ELLIPSIS.length();

    private static final String SEVERITY_FIELD_NAME = "severity";
    private static final String DEV_COMMENTS_FIELD_NAME = "dev-comments";
    private static final String DESCRIPTION_FIELD_NAME = "description";
    private static final String DETECTED_IN_BUILD_FIELD_NAME = "build-detected";
    private static final String CAUSED_BY_CHANGESET_FIELD_NAME = "changeset";
    private static final String NAME_FIELD_NAME = "name";
    private static final String CREATION_TIME_FIELD_NAME = "creation-time";
    private static final String DETECTED_BY_FIELD_NAME = "detected-by";
    private static final String STATUS_FIELD_NAME = "status";

    private static final String CATEGORY_LABEL_NAME = "Category";

    private static final String DEFECT_ENTITY_TYPE_NAME = "defect";

    private static final String ALM_URL = "almUrl";
    private static final String SEVERITY_PARAM_NAME = "severity";
    private static final String PROJECT_PARAM_NAME = "SSC_project";  // should not cause a conflict with ALM field names
    private static final String DOMAIN_PARAM_NAME = "SSC_domain";  // should not cause a conflict with ALM field names
    private static final String SUMMARY_PARAM_NAME = "summary";
    private static final String NAME_PARAM_NAME = "name";
    private static final String DESCRIPTION_PARAM_NAME = "description";

    private static final Charset CHARSET_UTF8 = Charset.forName("UTF-8");

    private static final String SUPPORTED_VERSIONS = "12.50";

    private static final String INTERRUPTED_BY_USER = "Interrupted by user";

    private String almUrlPrefix;
    private boolean isSecure;
    private String almHost;
    private int almPort;
    private String almProtocol;
    private HttpHost almTarget;

    private Map<String, String> config; // Full ALM plugin configuration

    private final StopLock stopLock = new StopLock();

    private static final String ALM_NOT_ACCESSIBLE = "The ALM server is not accessible. Check the plugin configuration and ensure that the server is not down or overloaded.";

    /**
     * Maximum number of candidate changesets that will be included in the bug description.
     */
    private static final int MAX_CANDIDATE_CHANGELISTS = 20;

    private final DocumentBuilder docBuilder;
    private final XPathFactory xpathFactory;

    // TODO: Configuring connMan this way brakes bug submission in AWB (Eclipse OSGI ?).
    // See also other related TODOs
    // Note: making connMan static did not help for AWB
    // private final PoolingHttpClientConnectionManager connMan;

    public AlmBugTrackerPlugin() {

        // SSC version 18.x notes for Apache PoolingHttpClientConnectionManager configuration:
        // ====================================================================================
        // A new bug tracker plugin instance is created in plugin framework always when setConfiguration(...) is called from SSC.
        //
        // Method setConfiguration(...) is called before every hi-level plugin API call that needs to communicate with
        // bug tracker provider, like testConfiguration(...), fileBug(...) etc.
        //
        // So every API call to ALM provider gets its own pooling connection manager.
        // Therefore for one successful plugin API call it should be probably enough if both following totals had been set even to 1,
        // but as not all possible Apache HTTP Client versions details and future changes in HTTP client are known,
        // let's give to these totals an acceptable safety reserve.

        // TODO: Configuring connMan this way brakes bug submission in AWB (Eclipse OSGI ?), even if SSC is ok with it.
        // Not enough time for it now so returning it back, but leaving it here commented for a possible further investigation.

//        connMan = new PoolingHttpClientConnectionManager();
//        connMan.setMaxTotal(5); // Max total connections maintained by pooling manager
//        connMan.setDefaultMaxPerRoute(5); // In our case route is defined by ALM host URL and optional proxy
//                                          // and for one API call remains persistent


        final DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        docFactory.setNamespaceAware(true); // never forget this!
        try {
            docBuilder = docFactory.newDocumentBuilder();
        } catch (final ParserConfigurationException e) {
            throw new RuntimeException(e);
        }

        xpathFactory = XPathFactory.newInstance();

    }

    // This class is used to keep a current query of working thread and to receive stop signal from another thread.
    // It is designed to maintain state per each thread, because BugtrackerPlugin is stateless singleton class
    // which is used to process multiple queries simultaneously.
    private static class StopLock {
        private HttpUriRequest currentRequest;
        private boolean isCurrentRequestStopped = false;

        synchronized void startRequest() {
            isCurrentRequestStopped = false;
            currentRequest = null;
        }

        synchronized void setCurrentQuery(HttpUriRequest query) {
            if (isAborted()) {
                throw new BugTrackerException(AlmBugTrackerPlugin.INTERRUPTED_BY_USER, new InterruptedException());
            }

            if (isCurrentRequestStopped && query != null) {
                query.abort();
            }

            currentRequest = query;
        }

        synchronized boolean isAborted() {
            return isCurrentRequestStopped;
        }

        synchronized void endRequest() {
            if (isAborted()) {
                throw new BugTrackerException(AlmBugTrackerPlugin.INTERRUPTED_BY_USER, new InterruptedException());
            }
            isCurrentRequestStopped = false;
            currentRequest = null;
        }

        synchronized void stop() {
            isCurrentRequestStopped = true;
            HttpUriRequest query = currentRequest;
            if (query != null) {
                query.abort();
            }
        }
    }

    @Override
    public void stop() {
        stopLock.stop();
    }

    private static class Response {
        private final int responseStatus;
        private final String responseBody;
        private final Document document;
        private final String location;

        public Response(int responseStatus, String responseBody, Document document, String location) {
            this.responseStatus = responseStatus;
            this.responseBody = responseBody;
            this.document = document;
            this.location = location;
        }

        int getResponseStatus() {
            return responseStatus;
        }

        String getResponseBody() {
            return responseBody;
        }

        Document getDocument() {
            return document;
        }

        String getLocation() {
            return location;
        }
    }

    /**
     * This method should be called at the beginning of each hi-level API call which uses http client,
     * kept persistent and used as a context for all subsequent http requests
     * during the whole particular API function processing.
     *
     * @return new HTTP client context set with with authorization cache
     */
    private HttpClientContext createHttpClientContext() {
        HttpClientContext httpContext = HttpClientContext.create();
        AuthCache authCache = new BasicAuthCache();
        authCache.put(almTarget, new BasicScheme());
        httpContext.setAuthCache(authCache);    // This enables using preemptive authorization for HTTP Client requests
        return httpContext;
    }

    private Response runQueryInContext(final CloseableHttpClient client, final HttpClientContext hcc, HttpUriRequest request) {

        stopLock.setCurrentQuery(request);
        CloseableHttpResponse httpResponse = null;
        try {
            httpResponse = client.execute(request, hcc);
            final int httpReturnCode = httpResponse.getStatusLine().getStatusCode();

            final Header locationHeader = httpResponse.getFirstHeader("Location");
            final String location = locationHeader == null ? null : locationHeader.getValue();

            HttpEntity entity = httpResponse.getEntity();
            final String responseString = entity == null ? null : EntityUtils.toString(entity);
            final Document doc = (responseString != null && responseString.length() > 0
                    && (httpReturnCode == HttpURLConnection.HTTP_OK || httpReturnCode == HttpURLConnection.HTTP_CREATED))
                    ? docBuilder.parse(makeInputSource(new ByteArrayInputStream(responseString.getBytes(CHARSET_UTF8)))) : docBuilder.newDocument();
            EntityUtils.consume(entity);

            return new Response(httpReturnCode, responseString, doc, location);

        } catch (final IOException e) {
            if (stopLock.isAborted()) {
                throw new BugTrackerException(INTERRUPTED_BY_USER, new InterruptedException());
            }
            throw new BugTrackerException(ALM_NOT_ACCESSIBLE, e);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        } finally {
            stopLock.setCurrentQuery(null);
            try {
                if (httpResponse != null) {
                    httpResponse.close();
                }
            } catch (IOException e) {
                LOG.warn("Unable to close HTTP response");
                if (LOG.isDebugEnabled()) {
                    LOG.debug(e);
                }
            }
        }
    }

    private HttpGet createRequestForBugXML(String bugId) {
        final HttpGet query;

        try {
            final String[] bugIdParts = bugId.split(":");
            if (bugIdParts.length != 3) {
                throw new IllegalArgumentException("Incorrect bug ID format");
            }
            final String domainName = bugIdParts[0];
            final String projectName = bugIdParts[1];
            final String bugNumber = bugIdParts[2];


            final URI uri = new URIBuilder(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/defects").addParameter("query", "{id[" + bugNumber + "]}").build();
            query = new HttpGet(uri);
            query.addHeader("Accept", "application/xml");
            return query;
        } catch (final URISyntaxException e) {
            throw new RuntimeException("Invalid URI format");
        }
    }

    @Override
    public Bug fetchBugDetails(String bugId, UserAuthenticationStore credentials) {

        final HttpGet query = createRequestForBugXML(bugId);
        Bug bug = null;
        final HttpClientContext hcc = createHttpClientContext();
        stopLock.startRequest();
        try (CloseableHttpClient client = authenticate(credentials.getUserName(), credentials.getPassword(), hcc)) {
            Response res = runQueryInContext(client, hcc, query);
            final int httpReturnCode = res.getResponseStatus();
            final String response = res.getResponseBody();
            Document doc = res.getDocument();
            final XPath xpath = xpathFactory.newXPath();
            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:

                    final int numResults = Integer.parseInt((String) xpath.compile("/Entities/@TotalResults").evaluate(doc, XPathConstants.STRING));

                    if (numResults == 0) {
                        return null;
                    }

                    final String bugStatus = (String) xpath.compile("/Entities/Entity/Fields/Field[@Name='status']/Value/text()").evaluate(doc,
                            XPathConstants.STRING);
                    bug = new Bug(bugId, bugStatus);
                    break;
                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + httpReturnCode + "; Response: " + response);
                    throw new BugTrackerException("Could not query defects from the ALM server", nested);
            }
        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            logClientCloseError(e);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        } finally {
            stopLock.endRequest();
        }

        return bug;
    }

    private String fetchBugComments(String bugId, UserAuthenticationStore credentials, final HttpClientContext hcc) {

        String bugComments = null;
        try (CloseableHttpClient client = authenticate(credentials.getUserName(), credentials.getPassword(), hcc)) {

            final HttpGet query = createRequestForBugXML(bugId);
            Response resp = runQueryInContext(client, hcc, query);

            final int httpReturnCode = resp.getResponseStatus();
            final String respBody = resp.getResponseBody();
            Document doc = resp.getDocument();
            final XPath xpath = xpathFactory.newXPath();

            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:
                    final int numResults = Integer.parseInt((String) xpath.compile("/Entities/@TotalResults").evaluate(doc, XPathConstants.STRING));
                    if (numResults > 0) {
                        bugComments = (String) xpath.compile("/Entities/Entity/Fields/Field[@Name='" + DEV_COMMENTS_FIELD_NAME + "']/Value/text()")
                                .evaluate(doc, XPathConstants.STRING);
                    }
                    break;
                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + httpReturnCode + "; Response: " + respBody);
                    throw new BugTrackerException("Could not query comments from the ALM server", nested);
            }
        } catch (IOException e) {
            logClientCloseError(e);
        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);
        }

        return bugComments;
    }

    @Override
    public Bug fileBug(BugSubmission bugSubmission, UserAuthenticationStore credentials) {

        Bug bug = null;
        final HttpClientContext hcc = createHttpClientContext();
        stopLock.startRequest();
        try (CloseableHttpClient client = authenticate(credentials.getUserName(), credentials.getPassword(), hcc)) {

            final String domainName = bugSubmission.getParams().get(DOMAIN_PARAM_NAME);
            final String projectName = bugSubmission.getParams().get(PROJECT_PARAM_NAME);

            validateAlmDomainAndProject(domainName, projectName, client, hcc);

            String detectedInBuildInstance = null;
            if (bugSubmission.getIssueDetail().getDetectedInBuild() != null) {
                try {
                    detectedInBuildInstance = getBuildInstanceIdFromRevision(bugSubmission.getIssueDetail().getDetectedInBuild()
                            , client, hcc, domainName, projectName);
                } catch (Exception e) {
                    LOG.warn("Skipping identification of build instance where issue was detected.", e);
                }
            }

            List<String> candidateChangesets = null;

            if (bugSubmission.getIssueDetail().getLastBuildWithoutIssue() != null && bugSubmission.getIssueDetail().getDetectedInBuild() != null) {
                try {
                    candidateChangesets = queryChangesetsBetween(
                            bugSubmission.getIssueDetail().getLastBuildWithoutIssue()
                            , bugSubmission.getIssueDetail().getDetectedInBuild()
                            , bugSubmission.getIssueDetail().getFileName()
                            , bugSubmission.getParams(), credentials, hcc);
                } catch (Exception e) {
                    LOG.warn("Skipping changeset discovery", e);
                }
            }

            HttpPost createDefect = new HttpPost(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/defects");
            createDefect.addHeader("Accept", "application/xml");

            final String defectXmlString = constructDefectXmlString(bugSubmission, detectedInBuildInstance, candidateChangesets, credentials.getUserName(),
                    getAttributeNameForEntity(DEFECT_ENTITY_TYPE_NAME, CATEGORY_LABEL_NAME, domainName, projectName, client, hcc));

            createDefect.setEntity(new StringEntity(defectXmlString, ContentType.create("application/xml", CHARSET_UTF8)));

            Response createDefectResponse = runQueryInContext(client, hcc, createDefect);

            final XPath xpath = xpathFactory.newXPath();

            switch (createDefectResponse.getResponseStatus()) {
                case HttpURLConnection.HTTP_CREATED:
                    final String bugId = composeBugId(domainName, projectName, extractBugNumber(xpath, createDefectResponse.getDocument()));
                    final String bugStatus = extractBugStatus(xpath, createDefectResponse.getDocument());
                    final String location = createDefectResponse.getLocation();

                    if (location != null) {
                        uploadBugAttachment(client, hcc, bugSubmission.getIssueDetail(), location);
                    } else {
                        LOG.warn("Could not upload URL attachment file to defect (Location not found in response).");
                    }
                    destroyAlmSession(client, hcc);
                    bug = new Bug(bugId, bugStatus);
                    break;
                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + createDefectResponse.getResponseStatus() + "; Response: " + createDefectResponse.getResponseBody());

                    String reason = null;
                    try {
                        InputSource is = new InputSource(new StringReader(createDefectResponse.getResponseBody()));
                        is.setEncoding("UTF-8");
                        Document document = docBuilder.parse(is);
                        reason = (String) xpath.compile("/QCRestException/Title/text()").evaluate(document, XPathConstants.STRING);

                        List<BugParam> params = queryBugParameters(
                                bugSubmission.getIssueDetail(), domainName, projectName, client, hcc);
                        for (BugParam param : params) {
                            reason = reason.replaceAll(param.getIdentifier(), param.getDisplayLabel());
                        }
                    } catch (Exception e) {
                        LOG.warn(e);
                    }
                    destroyAlmSession(client, hcc);

                    throw new BugTrackerException(String.format("Could not create a bug on the ALM server %s", reason != null ? ": \n" + reason : "."), nested);
            }
        } catch (final IOException e) {
            logClientCloseError(e);
        } catch (BugTrackerException e) {
            throw e;
        } catch (final Exception e) {
            throw new RuntimeException(e);
        } finally {
            stopLock.endRequest();
        }

        return bug;
    }


    @Override
    public List<BugParam> getBugParameters(IssueDetail issueDetail, UserAuthenticationStore credentials) {

        final HttpClientContext hcc = createHttpClientContext();
        List<BugParam> bugParams = new ArrayList<>();
        stopLock.startRequest();
        try (CloseableHttpClient client = authenticate(credentials.getUserName(), credentials.getPassword(), hcc)){
            bugParams = getBugParameters(issueDetail, client, hcc, null, null);
            return bugParams;
        } catch (IOException e) {
            logClientCloseError(e);
            return bugParams;
        } finally {
            stopLock.endRequest();
        }
    }

    private List<BugParam> getBugParameters(IssueDetail issueDetail
            , final CloseableHttpClient client, final HttpClientContext hcc, String domain, String project) {

        List<BugParam> bugParams = new ArrayList<>();

        final List<String> domains = getDomains(client, hcc);
        final BugParam domainParam = new BugParamChoice().setChoiceList(domains).setHasDependentParams(true).setIdentifier(DOMAIN_PARAM_NAME)
                .setDisplayLabel("ALM Domain").setRequired(true).setDescription("ALM Domain against which bug is to be filed");
        bugParams.add(domainParam);
        final BugParam projectParam = new BugParamChoice().setHasDependentParams(true).setIdentifier(PROJECT_PARAM_NAME).setDisplayLabel("ALM Project")
                .setRequired(true).setDescription("ALM Project against which bug is to be filed");
        bugParams.add(projectParam);
        if (!StringUtils.isEmpty(domain)) {
            if (domains.contains(domain)) {
                final List<String> projects = getProjects(issueDetail, client, hcc, domain);
                ((BugParamChoice) projectParam).setChoiceList(projects);
                if (!StringUtils.isEmpty(project)) {
                    if (projects.contains(project)) {
                        bugParams.addAll(
                                queryBugParameters(issueDetail, domain, project, client, hcc)
                        );
                    }
                }
            }
        }
        return bugParams;
    }

    private List<BugParam> queryBugParameters(IssueDetail issueDetail, String domain, String project
            , final CloseableHttpClient client, final HttpClientContext hcc) {

        List<BugParam> bugParams = new ArrayList<>();
        HttpGet query = createRequestForBugFieldsXML(domain, project);
        Response resp;
        try {
            resp = runQueryInContext(client, hcc, query);
            final int httpReturnCode = resp.getResponseStatus();
            String response = resp.getResponseBody();
            final Document doc = resp.getDocument();
            final XPath xpath = xpathFactory.newXPath();
            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:
                    final NodeList nodes = (NodeList) xpath.compile("/Fields/Field").evaluate(doc, XPathConstants.NODESET);
                    for (int i = 0; i < nodes.getLength(); i++) {
                        BugParam bugParam;
                        String type = "", listId = "";
                        boolean required = false;
                        int size = 0;
                        Element field = (Element) nodes.item(i);
                        String identifier = field.getAttribute("Name");
                        String displayName = field.getAttribute("Label");
                        BugParam summaryParam = null;
                        BugParam descriptionParam = null;

                        NodeList childNodes = field.getChildNodes();
                        for (int j = 0; j < childNodes.getLength(); j++) {
                            Node childNode = childNodes.item(j);
                            if (childNode.getNodeName().equals("Type")) {
                                type = childNode.getTextContent();
                            } else if (childNode.getNodeName().equals("Required")) {
                                required = Boolean.parseBoolean(childNode.getTextContent());
                            } else if (childNode.getNodeName().equals("Size")) {
                                size = Integer.parseInt(childNode.getTextContent());
                            } else if (childNode.getNodeName().equals("List-Id")) {
                                listId = childNode.getTextContent();
                            }
                        }
                        if (required || "description".equals(identifier)) {
                            if (type.equals("String") || type.equals("Number") || type.equals("Memo")) {
                                if (size == -1) {
                                    bugParam = new BugParamTextArea();
                                } else {
                                    bugParam = new BugParamText();
                                }
                                bugParam.setDisplayLabel(displayName);
                                bugParam.setIdentifier(identifier);
                                bugParam.setRequired(required);
                                bugParam.setMaxLength(size);
                                if ("description".equals(identifier)) {
                                    if (issueDetail == null) {
                                        bugParam.setValue("Issue Ids: $ATTRIBUTE_INSTANCE_ID$\n$ISSUE_DEEPLINK$");
                                    } else {
                                        bugParam.setValue(pluginHelper.buildDefaultBugDescription(issueDetail, true));
                                    }
                                    descriptionParam = bugParam;
                                } else if ("name".equals(identifier)) {
                                    if (issueDetail == null) {
                                        bugParam.setValue("Fix $ATTRIBUTE_CATEGORY$ in $ATTRIBUTE_FILE$");
                                    } else {
                                        bugParam.setValue(issueDetail.getSummary());
                                    }
                                    summaryParam = bugParam;
                                } else {
                                    // add descriptionParam and summaryParam later
                                    bugParams.add(bugParam);
                                }
                            } else if (type.equalsIgnoreCase("lookuplist")) {
                                HttpGet listQuery = getLookupListQuery(domain, project, listId, ALMApiVersion.VER_11);
                                Response listresp = runQueryInContext(client, hcc, listQuery);
                                int listHttpReturnCode = listresp.getResponseStatus();
                                // It's not a very smart solution, but I could not find a way to know the version of ALM
                                // server. So, I need to check both possible urls for getting the lists.
                                // If first one is not working, it means that most likly we are working with ALM 11.52.
                                if (listHttpReturnCode != HttpURLConnection.HTTP_OK) {
                                    listQuery = getLookupListQuery(domain, project, listId, ALMApiVersion.VER_11_52);
                                    listresp = runQueryInContext(client, hcc, listQuery);
                                    listHttpReturnCode = listresp.getResponseStatus();
                                }
                                String listResponse = listresp.getResponseBody();
                                final Document listDoc = listresp.getDocument();
                                final XPath listXpath = xpathFactory.newXPath();
                                switch (listHttpReturnCode) {
                                    case HttpURLConnection.HTTP_OK:
                                        final NodeList choices = (NodeList) listXpath.compile("/Lists/List/Items/Item").evaluate(listDoc,
                                                XPathConstants.NODESET);
                                        List<String> choiceList = new ArrayList<>();
                                        for (int l = 0; l < choices.getLength(); l++) {
                                            Element itemElem = (Element) choices.item(l);
                                            itemElem.getAttribute("value");
                                            String value = itemElem.getAttributes().getNamedItem("value").getTextContent();
                                            choiceList.add(value);
                                        }
                                        bugParam = new BugParamChoice().setChoiceList(choiceList);
                                        bugParam.setDisplayLabel(displayName);
                                        bugParam.setIdentifier(identifier);
                                        bugParam.setRequired(required);
                                        bugParam.setMaxLength(size);
                                        bugParams.add(bugParam);
                                        break;
                                    default:
                                        RuntimeException nested = new RuntimeException("Got HTTP return code: " + listHttpReturnCode + "; Response: "
                                                + listResponse);
                                        throw new BugTrackerException("Could not query comments from the ALM server", nested);
                                }
                            } else if (type.equalsIgnoreCase("date") && !CREATION_TIME_FIELD_NAME.equals(identifier)) {
                                bugParam = new BugParamText();
                                bugParam.setDisplayLabel(displayName);
                                bugParam.setIdentifier(identifier);
                                bugParam.setRequired(required);
                                bugParam.setValue(new SimpleDateFormat("yyyy-MM-dd").format(new Date()));
                                bugParams.add(bugParam);
                            } else if (type.equalsIgnoreCase("userslist") && !DETECTED_BY_FIELD_NAME.equals(identifier)) {
                                List<String> users = getUsers(client, hcc, domain, project);
                                if (users != null) {
                                    bugParam = new BugParamChoice().setChoiceList(users);
                                } else {
                                    bugParam = new BugParamText();
                                }
                                bugParam.setDisplayLabel(displayName);
                                bugParam.setIdentifier(identifier);
                                bugParam.setRequired(required);
                                bugParam.setMaxLength(size);
                                bugParams.add(bugParam);
                            } else {
                                continue;
                            }
                        }
                        // add summary and description params
                        // order is domain, project ,summary, description, everything else...
                        if (descriptionParam != null) {
                            descriptionParam.setRequired(true);
                            bugParams.add(0, descriptionParam);
                        }
                        if (summaryParam != null) {
                            summaryParam.setRequired(true);
                            bugParams.add(0, summaryParam);
                        }
                    }
                    break;
                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + httpReturnCode + "; Response: " + response);
                    throw new BugTrackerException("Could not query default bug fields from the ALM server", nested);
            }

        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);
        }

        return bugParams;
    }

    private HttpGet getLookupListQuery(final String domainName, final String projectName, final String id, ALMApiVersion almApiVersion) {
        String listsUrl;
        if (almApiVersion == ALMApiVersion.VER_11_52) {
            listsUrl = "used-lists";
        } else {
            listsUrl = "lists";
        }

        final HttpGet query = new HttpGet(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/customization/" + listsUrl + "?id=" + id);
        query.addHeader("Accept", "application/xml");
        return query;
    }

    private HttpGet createRequestForBugFieldsXML(final String domainName, final String projectName) {
        final HttpGet query = new HttpGet(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/customization/entities/defect/fields");
        query.addHeader("Accept", "application/xml");
        return query;
    }

    /**
     * Proxy fnction with nin array argumante. See comment to the queryChangesetsBetween function for more detailed information.
     */
    private List<String> queryChangesetsBetween(String greaterThanRevision, String lesserThanOrEqualToRevision
            , String touchingFilePath, Map<String, String> bugParams
            , UserAuthenticationStore credentials, final HttpClientContext hcc) {

        return queryChangesetsBetween(Collections.singletonList(greaterThanRevision)
                , Collections.singletonList(lesserThanOrEqualToRevision)
                , touchingFilePath, bugParams, credentials, hcc);
    }

    /*
     * This implementation assumes that revision field of changeset-file entity corresponds to the snapshot version of the repository, which is what is tagged
     * for our scans and passed in as parameters for this method. This may not be true for VCSes like CVS and ClearCase which maintain revisions based on file,
     * and not changesets.
     *
     * This was tested successfully with ALM11+ALI1 hooked to a Subversion repository
     */
    private List<String> queryChangesetsBetween(Collection<String> greaterThanRevision, Collection<String> lesserThanOrEqualToRevision
                    , String touchingFilePath, Map<String, String> bugParams
                    , UserAuthenticationStore credentials, final HttpClientContext hcc) {

        Response resp;
        final List<String> candidateRevisions = new ArrayList<>();
        try (CloseableHttpClient client = authenticate(credentials.getUserName(), credentials.getPassword(), hcc)) {

            final String domainName = bugParams.get(DOMAIN_PARAM_NAME);
            final String projectName = bugParams.get(PROJECT_PARAM_NAME);

            validateAlmDomainAndProject(domainName, projectName, client, hcc);

			/*
             * This information is not available in a straightforward way since revision field of changeset-file is a string and only lexicographic ordering can
			 * be used. Numeric ordering is not available.
			 *
			 * Hence we first get the commit times of each of the two boundary revisions provided by querying the changesets. Then we query for changesets that
			 * touch our concerned file, and also fall between the two commit times
			 */
            final List<String> startDates = new ArrayList<>();
            final List<String> endDates = new ArrayList<>();

            for (final String revision : greaterThanRevision) {
                startDates.add(getChangesetDateFromRevision(revision, client, hcc, domainName, projectName));
            }

            for (final String revision : lesserThanOrEqualToRevision) {
                endDates.add(getChangesetDateFromRevision(revision, client, hcc, domainName, projectName));
            }

            final String startDate = (startDates.isEmpty() ? null : startDates.get(0));
            final String endDate = (endDates.isEmpty() ? null : endDates.get(endDates.size() - 1));

            final StringBuilder filter = new StringBuilder("{date[");
            if (greaterThanRevision != null) {
                filter.append("> '").append(startDate).append("' AND ");
            }
            filter.append("<= '").append(endDate).append("']; changeset-file.path['*").append(touchingFilePath).append("']}");

            final URI uri = new URIBuilder(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/changesets")
                    .addParameter("page-size", String.valueOf(MAX_CANDIDATE_CHANGELISTS))
                    .addParameter("query", filter.toString())
                    .addParameter("order-by", "{date[DESC]}").build();

            final HttpGet query = new HttpGet(uri);
            query.addHeader("Accept", "application/xml");

            resp = runQueryInContext(client, hcc, query);

            final int httpReturnCode = resp.getResponseStatus();
            final String response = resp.getResponseBody();
            destroyAlmSession(client, hcc);

            final Document doc = resp.getDocument();
            final XPath xpath = xpathFactory.newXPath();

            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:
                    final NodeList nodes = (NodeList) xpath.compile("/Entities/Entity/Fields/Field[@Name='id']/Value").evaluate(doc, XPathConstants.NODESET);
                    for (int i = 0; i < nodes.getLength(); i++) {
                        candidateRevisions.add(nodes.item(i).getTextContent());
                    }
                    break;
                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + httpReturnCode + "; Response: " + response);
                    throw new BugTrackerException("Could not query changesets from the ALM server", nested);
            }

            return candidateRevisions;

        } catch (IOException e) {
            logClientCloseError(e);
            return candidateRevisions;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<BugTrackerConfig> getConfiguration() {
        final BugTrackerConfig supportedVersions = new BugTrackerConfig().setIdentifier(BugTrackerPluginConstants.DISPLAY_ONLY_SUPPORTED_VERSION).setDisplayLabel("Supported Versions")
                .setDescription("Bug Tracker versions supported by the plugin").setValue(SUPPORTED_VERSIONS).setRequired(false);

        final BugTrackerConfig almUrlConfig = new BugTrackerConfig().setIdentifier(ALM_URL).setDisplayLabel("ALM URL")
                .setDescription("URL at which ALM REST API is accessible. Example: http://w2k3r2sp2:8080").setRequired(true);

        List<BugTrackerConfig> configs = new ArrayList<>(Arrays.asList(supportedVersions, almUrlConfig));
        configs.addAll(buildSscProxyConfiguration());
        pluginHelper.populateWithDefaultsIfAvailable(configs);
        return configs;

    }

    private List<BugTrackerConfig> buildSscProxyConfiguration() {
        List<BugTrackerConfig> proxyConfigs = new ArrayList<>();
        for (ProxyField fld : EnumSet.allOf(ProxyField.class)) {
            proxyConfigs.add(new BugTrackerConfig()
                    .setIdentifier(fld.getFieldName())
                    .setDisplayLabel(fld.getDisplayLabel())
                    .setDescription(fld.getDisplayLabel() + " for bug tracker plugin")
                    .setRequired(false));
        }
        return proxyConfigs;
    }

    @Override
    public String getLongDisplayName() {
        return "ALM at " + almUrlPrefix;
    }

    @Override
    public String getShortDisplayName() {
        return "ALM";
    }

    @Override
    public List<BugParam> onParameterChange(IssueDetail issueDetail, String changedParamIdentifier
            , List<BugParam> currentValues, UserAuthenticationStore credentials) {

        List<BugParam> returnParams = new ArrayList<>();
        final HttpClientContext hcc = createHttpClientContext();
        stopLock.startRequest();
        try (CloseableHttpClient client = authenticate(credentials.getUserName(), credentials.getPassword(), hcc)){

            boolean isDomainChanged = DOMAIN_PARAM_NAME.equals(changedParamIdentifier);
            boolean isProjectChanged = PROJECT_PARAM_NAME.equals(changedParamIdentifier);

            if (isDomainChanged) {
                BugParamChoice projectParam = (BugParamChoice) pluginHelper.findParam(PROJECT_PARAM_NAME, currentValues);

                BugParam domainParam = pluginHelper.findParam(DOMAIN_PARAM_NAME, currentValues);
                if (StringUtils.isEmpty(domainParam.getValue())) {
                    projectParam.setChoiceList(Collections.<String>emptyList());
                } else {
                    projectParam.setChoiceList(getProjects(issueDetail, client, hcc, domainParam.getValue()));
                }
                projectParam.setValue(null);
                returnParams = currentValues;
            } else if (isProjectChanged) {
                String domain = pluginHelper.findParam(DOMAIN_PARAM_NAME, currentValues).getValue();
                String project = pluginHelper.findParam(PROJECT_PARAM_NAME, currentValues).getValue();
                returnParams = getBugParameters(issueDetail, client, hcc, domain, project);
                for (BugParam bugParam : returnParams) {
                    BugParam currentParam = pluginHelper.findParam(bugParam.getIdentifier(), currentValues);
                    if (currentParam != null) {
                        bugParam.setValue(currentParam.getValue());
                    }
                }
            } else {
                throw new IllegalArgumentException("We should not be getting any other parameter since we didn't mark any other param as having dependent params");
            }

            return returnParams;

        } catch (IOException e) {
            logClientCloseError(e);
            return returnParams;
        } finally {
            stopLock.endRequest();
        }
    }

    @Override
    public boolean requiresAuthentication() {
        return true;
    }

    @Override
    public void setConfiguration(Map<String, String> config) {

        this.config = config;

        almUrlPrefix = config.get(ALM_URL);

        if (almUrlPrefix == null) {
            throw new IllegalArgumentException("Invalid configuration passed");
        }

        if (!almUrlPrefix.startsWith(HTTP_PROTOCOL + "://") && !almUrlPrefix.startsWith(HTTPS_PROTOCOL + "://")) {
            throw new BugTrackerException(String.format("ALM URL protocol should be either %s or %s", HTTP_PROTOCOL, HTTPS_PROTOCOL));
        }

        if (almUrlPrefix.endsWith("/")) {
            almUrlPrefix = almUrlPrefix.substring(0, almUrlPrefix.length() - 1);
        }

        try {
            URL almUrl = new java.net.URL(almUrlPrefix);
            almUrl.toURI();
            almHost = almUrl.getHost();
            if (almHost.length() == 0) {
                throw new BugTrackerException("ALM host name cannot be empty.");
            }
            almProtocol = almUrl.getProtocol();
            isSecure = almProtocol.equals(HTTPS_PROTOCOL);
            almPort = almUrl.getPort();
            if (almPort == -1) {
				/* Not specified */
                almPort = isSecure ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;
            }
            almTarget = new HttpHost(almHost, almPort, almProtocol);
        } catch (MalformedURLException | URISyntaxException e) {
            throw new BugTrackerException("Invalid ALM URL: " + almUrlPrefix);
        }

    }

    @Override
    public void testConfiguration(com.fortify.pub.bugtracker.support.UserAuthenticationStore credentials) {
        validateCredentials(credentials);
    }

    @Override
    public void validateCredentials(UserAuthenticationStore credentials) throws RuntimeException {

        stopLock.startRequest();
        final HttpClientContext hcc = createHttpClientContext();
        try (CloseableHttpClient client = authenticate(credentials.getUserName(), credentials.getPassword(), hcc)) {
            destroyAlmSession(client, hcc);
        } catch (IOException e) {
            logClientCloseError(e);
        } finally {
            stopLock.endRequest();
        }
    }

    @Override
    public String getBugDeepLink(String bugId) {

        final String[] bugIdParts = bugId.split(":");
        if (bugIdParts.length != 3) {
            throw new IllegalArgumentException();
        }
        final String domainName = bugIdParts[0];
        final String projectName = bugIdParts[1];
        final String bugNumber = bugIdParts[2];

        return getTdProtocol() + "://" + projectName + "." + domainName + "." + almHost + ":" + almPort
                + "/qcbin/DefectsModule-000000004243046514?EntityType=IBug&ShowDetails=Y&EntityID=" + bugNumber;

    }

    private Integer portToNumber (final String port) {
        Integer portNum = null;
        try {
            portNum = Integer.valueOf(port);
        } catch (NumberFormatException e) {
            LOG.warn(String.format("Port %s could not be converted to number - returning null", port));
        }
        return portNum;
    }

    private HttpHost resolveSscProxy(final Map<String, String> config, final String targetProtocol) {
        String proxyScheme = HTTP_PROTOCOL; // We don't support secure proxies (these working as SSL server itself)
                                            // hence proxyScheme (protocol) will be always "http"
        if (HTTPS_PROTOCOL.equals(targetProtocol)) {
            return getSscProxyHost(config.get(ProxyField.HTTPS_PROXY_HOST.getFieldName())
                    , config.get(ProxyField.HTTPS_PROXY_PORT.getFieldName()), proxyScheme);
        } else
            return getSscProxyHost(config.get(ProxyField.HTTP_PROXY_HOST.getFieldName())
                    , config.get(ProxyField.HTTP_PROXY_PORT.getFieldName()), proxyScheme);
    }

    private Credentials resolveSscProxyCredentials(final Map<String, String> config, final String targetProtocol) {
        if (HTTPS_PROTOCOL.equals(targetProtocol)) {
            String userName = config.get(ProxyField.HTTPS_PROXY_USERNAME.getFieldName());
            if (userName == null) {
                return null;
            } else {
                return new UsernamePasswordCredentials(config.get(ProxyField.HTTPS_PROXY_USERNAME.getFieldName())
                        , config.get(ProxyField.HTTPS_PROXY_PASSWORD.getFieldName()));
            }
        } else {
            String userName = config.get(ProxyField.HTTP_PROXY_USERNAME.getFieldName());
            if (userName == null) {
                return null;
            } else {
                return new UsernamePasswordCredentials(config.get(ProxyField.HTTP_PROXY_USERNAME.getFieldName())
                        , config.get(ProxyField.HTTP_PROXY_PASSWORD.getFieldName()));
            }
        }
    }

    private HttpHost getSscProxyHost(final String sscProxyHostname, final String sscProxyPort, String proxyScheme) {
        HttpHost proxyHost = null;
        if (!StringUtils.isEmpty(sscProxyHostname) && !sscProxyHostname.equals(PROXY_EMPTY_VALUE)) {
            Integer sscProxyPortNum = portToNumber(sscProxyPort);
            if (sscProxyPortNum == null || sscProxyPortNum < 1) {
                throw new BugTrackerException(String.format(
                        "Error in bug tracker proxy configuration - SSC proxy host is '%s' but port is '%s'", sscProxyHostname, sscProxyPort));
            } else {
                proxyHost = new HttpHost(sscProxyHostname, sscProxyPortNum, proxyScheme);
            }
        }
        return proxyHost;
    }

    private CloseableHttpClient authenticate(final String username, final String password, final HttpClientContext hcc)
            throws BugTrackerException {

        final CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(new AuthScope(almTarget), new UsernamePasswordCredentials(username, password));

        RequestConfig defaultRequestConfig = RequestConfig.custom()
                .setConnectTimeout(5 * 1000)    // Timeout for receiving a free connection from pooling connection manager
                                                // As we are using a dedicated connection manager per API call
                                                //   there should be always free connections available.
                .setConnectionRequestTimeout(5 * 1000)  // Taking 5 seconds as an acceptable timeout for waiting
                                                        //   for an answer to the http(s) request.
                .setSocketTimeout(10 * 1000) // Taking 10 seconds as an acceptable timeout for waiting
                                            //   for data to be sent from target to the client.
                .build();

        // Following headers can change a default behaviour of some proxies in terms of that the data sent from target
        // to proxy are not cached on the proxy. As a result http client will receive always current data from the target.
        List<Header> defaultClientHeaders = new ArrayList<>();
        defaultClientHeaders.add(new BasicHeader(HttpHeaders.PRAGMA, "no-cache"));
        defaultClientHeaders.add(new BasicHeader(HttpHeaders.CACHE_CONTROL, "no-cache"));

        HttpHost sscProxy = resolveSscProxy(config, almProtocol);

        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create()
                // TODO: Using connMan this way brakes bug submission in AWB (Eclipse OSGI ?).
                // See also other related TODOs in this class
                // .setConnectionManager(connMan)
                .setDefaultCredentialsProvider(credsProvider)
                .setDefaultRequestConfig(defaultRequestConfig)
                .setDefaultHeaders(defaultClientHeaders)
                .setRetryHandler(new DefaultHttpRequestRetryHandler(3, true))
                    // Setting the previous requestSentRetryEnabled=true helped filing bugs through less responsive proxy
                    // (specifically a Tiny proxy). This parameter affects retrying only non idempotent methods (POST in case of ALM)
                    // idempotent methods GET and PUT are always retried.
                    // Note: if responses to POST are not being returned but the requests are reaching ALM it could happen
                    // that unwanted/not tracked/dead resources are created on the bug tracker provider side. In this case
                    // it should be considered switching POST retries off.
                .setDefaultCookieStore(new BasicCookieStore());

        if (sscProxy == null) {
            httpClientBuilder
                .useSystemProperties(); // Keeping this for backward plugin compatibility if the  SSC proxy is not used
                                        // Among other system properties http(s).proxyHost, http(s).proxyPort httpNonProxyHosts are taken into account
                                        // For the complete list see http://hc.apache.org/httpcomponents-client-ga/httpclient/apidocs/org/apache/http/impl/client/HttpClientBuilder.html
        } else {
            Credentials proxyCreds = resolveSscProxyCredentials(config, almProtocol);
            if (proxyCreds != null) {
                credsProvider.setCredentials(new AuthScope(sscProxy.getHostName(), sscProxy.getPort()), proxyCreds);
            }
            httpClientBuilder
                .setProxy(sscProxy);
        }
        CloseableHttpClient httpClient = httpClientBuilder.build();

        HttpUriRequest authRequest = RequestBuilder.post()
                .setUri(almUrlPrefix + "/qcbin/authentication-point/authenticate")
                .setHeader(HttpHeaders.ACCEPT, "application/xml")
                .build();

        final int authStatus = runQueryInContext(httpClient, hcc, authRequest).getResponseStatus();
        switch (authStatus) {
            case HttpURLConnection.HTTP_OK:
                HttpUriRequest sessionRequest = RequestBuilder.post()
                        .setUri(almUrlPrefix + "/qcbin/rest/site-session")
                        .setHeader(HttpHeaders.ACCEPT, "application/xml")
                        .build();
                final int sessionStatus = runQueryInContext(httpClient, hcc, sessionRequest).getResponseStatus();
                if (!(sessionStatus == HttpURLConnection.HTTP_CREATED || sessionStatus == HttpURLConnection.HTTP_OK)) {
                    throw new BugTrackerAuthenticationException("Problem getting ALM QCSession cookie");
                }
                break;
            case HttpURLConnection.HTTP_UNAUTHORIZED:
                throw new BugTrackerAuthenticationException("The ALM credentials provided are invalid");
            case HttpURLConnection.HTTP_PROXY_AUTH:
                throw new BugTrackerAuthenticationException("The http(s) proxy credentials provided are invalid");
            default:
                throw new BugTrackerAuthenticationException("ALM authorization failed");
        }

        return httpClient;
    }

    private void destroyAlmSession(final CloseableHttpClient client, final HttpClientContext hcc) {

        HttpUriRequest deleteSession = RequestBuilder.delete()
                .setUri(almUrlPrefix + "/qcbin/rest/site-session")
                .build();
        runQueryInContext(client, hcc, deleteSession);
    }

    private String constructDefectXmlString(BugSubmission bug, String detectedInBuildInstanceId
            , List<String> candidateChangesets, String detectedByUser, String categoryAttributeName) throws Exception {

        final Entity defect = new Entity();
        defect.setType(DEFECT_ENTITY_TYPE_NAME);
        final Entity.Fields fields = new Entity.Fields();
        defect.setFields(fields);

        fields.getField().add(buildEntityField(DETECTED_BY_FIELD_NAME, detectedByUser, DEFAULT_TRIM_LENGTH));

        fields.getField().add(buildEntityField(CREATION_TIME_FIELD_NAME, new SimpleDateFormat("yyyy-MM-dd").format(new Date()), DEFAULT_TRIM_LENGTH));

        if (categoryAttributeName != null && categoryAttributeName.length() != 0) {
            fields.getField().add(buildEntityField(categoryAttributeName, "Fortify - " + bug.getIssueDetail().getAnalysisType(), DEFAULT_TRIM_LENGTH));
        }

        fields.getField().add(buildEntityField(NAME_FIELD_NAME
                , (anyNotNull(bug.getParams().get(SUMMARY_PARAM_NAME), bug.getParams().get(NAME_PARAM_NAME))), DEFAULT_TRIM_LENGTH));

        if (detectedInBuildInstanceId != null && detectedInBuildInstanceId.length() != 0) {
            fields.getField().add(buildEntityField(DETECTED_IN_BUILD_FIELD_NAME, detectedInBuildInstanceId, DEFAULT_TRIM_LENGTH));
        }

        if (candidateChangesets != null && candidateChangesets.size() == 1) {
            fields.getField().add(buildEntityField(CAUSED_BY_CHANGESET_FIELD_NAME, candidateChangesets.get(0), DEFAULT_TRIM_LENGTH));
        }

        fields.getField().add(buildEntityField(DESCRIPTION_FIELD_NAME
                , convertToHtml(massageBugDescription(bug.getParams().get(DESCRIPTION_PARAM_NAME), candidateChangesets)), DEFAULT_DESCRIPTION_TRIM_LENGTH));

        if (bug.getIssueDetail().getComments() != null) {
            final StringBuilder allComments = new StringBuilder();
            for (final IssueComment c : bug.getIssueDetail().getComments()) {
                allComments.append("[").append(c.getUsername()).append(" on ").append(c.getTimestamp()).append("]: ").append(c.getBody());
                allComments.append("\n\n");
            }
            fields.getField().add(buildEntityField(DEV_COMMENTS_FIELD_NAME, convertToHtml(allComments.toString()), DEFAULT_COMMENTS_TRIM_LENGTH));
        }

        fields.getField().add(buildEntityField(SEVERITY_FIELD_NAME, bug.getParams().get(SEVERITY_PARAM_NAME), DEFAULT_TRIM_LENGTH));

        for (String paramName : bug.getParams().keySet()) {
            if (!(paramName.equals(NAME_PARAM_NAME) || paramName.equals(DESCRIPTION_PARAM_NAME) ||
                    paramName.equals(PROJECT_PARAM_NAME) || paramName.equals(DOMAIN_PARAM_NAME)
                    || paramName.equals(SEVERITY_PARAM_NAME))) {
                fields.getField().add(buildEntityField(paramName, bug.getParams().get(paramName), DEFAULT_TRIM_LENGTH));
            }
        }

        final String defectXmlString = EntityMarshallingUtils.marshal(Entity.class, defect);
        LOG.debug("defectXmlString: " + defectXmlString);
        return defectXmlString;
    }

    private List<String> getUsers(final CloseableHttpClient client, final HttpClientContext hcc
            , String domainName, String projectName) {

        List<String> res = new ArrayList<>();
        final HttpGet query = new HttpGet(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/customization/users");
        query.addHeader("Accept", "application/xml");

        Response resp = runQueryInContext(client, hcc, query);
        if (resp.getResponseStatus() == HttpURLConnection.HTTP_OK) {
            try {
                XPath xpath = xpathFactory.newXPath();
                NodeList userNodes = (NodeList) xpath.compile("/Users/User/@Name").evaluate(resp.getDocument(), XPathConstants.NODESET);
                for (int i = 0; i < userNodes.getLength(); i++) {
                    res.add(userNodes.item(i).getTextContent());
                }
            } catch (XPathExpressionException e) {
                throw new RuntimeException(e);
            }
        } else {
            LOG.warn(String.format("Could not query user list from the ALM server. Got HTTP return code: %s; Response: %s", resp.getResponseStatus(), resp.getResponseBody()));
            return null;
        }
        return res;
    }

    private String getBuildInstanceIdFromRevision(String revision
            , final CloseableHttpClient client, final HttpClientContext hcc
            , String domainName, String projectName) {

        final String changesetId;
        Response resp;
        try {
			/* First find out the changsetId from revision number */
            final URI uri = new URIBuilder(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/changesets")

                    .addParameter("page-size", "1")
                    .addParameter("query", "{changeset-file.revision['" + revision + "']}")
                    .build();
            final HttpGet query = new HttpGet(uri);
            query.addHeader("Accept", "application/xml");

            resp = runQueryInContext(client, hcc, query);
            int httpReturnCode = resp.getResponseStatus();
            String response = resp.getResponseBody();

            Document doc = resp.getDocument();
            XPath xpath = xpathFactory.newXPath();
            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:
                    changesetId = (String) xpath.compile("/Entities/Entity/Fields/Field[@Name='id']/Value/text()").evaluate(doc, XPathConstants.STRING);
                    if (changesetId == null || changesetId.length() == 0) {
                        LOG.warn(String.format("Could not query revisions from ALM. Revision %s does not correspond to a changeset-file revision", revision));
                        return null;
                    }
                    break;
                default:
                    LOG.warn(String.format("Could not query changesets from the ALM server. Got HTTP return code: %s; Response: %s", httpReturnCode, response));
                    return null;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

		/* Using the changeset id, get the build instance id */
        try {
            final URI uri = new URIBuilder(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/changeset-links")
                    .addParameter("page-size", "1")
                    .addParameter("query", "{to-endpoint-type[build-instance];from-endpoint-type[changeset];from-endpoint-id[" + changesetId + "]}")
                    .build();
            final HttpGet query = new HttpGet(uri);
            query.addHeader("Accept", "application/xml");

            resp = runQueryInContext(client, hcc, query);
            int httpReturnCode = resp.getResponseStatus();
            String response = resp.getResponseBody();

            Document doc = resp.getDocument();
            XPath xpath = xpathFactory.newXPath();
            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:
                    final String buildInstanceId = (String) xpath.compile("/Entities/Entity/Fields/Field[@Name='to-endpoint-id']/Value/text()").evaluate(doc,
                            XPathConstants.STRING);
                    if (buildInstanceId == null || buildInstanceId.length() == 0) {
                        LOG.warn(String.format("Could not query build-instance from ALM. Changeset Id '%s' does not correspond to a build-instance", changesetId));
                        return null;
                    }
                    return buildInstanceId;
                default:
                    LOG.warn(String.format("Could not query build-instances from the ALM server. Got HTTP return code: %s; Response: %s", httpReturnCode, response));
                    return null;
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Needed because ALM descriptions need to be HTML. Otherwise newline characters dont display correctly
     */
    private String convertToHtml(String description) {

        return "<html><body><p>" + description.replaceAll("[\n\r]+", "</p><p>") + "</p></body></html>";
    }

    private String convertCommentToHtml(String comment, String username) {

        return "<html><body><div align=\"left\"><font fact=\"Arial\"><span style=\"font-size:8pt\"><br/></span></font>"
                + "<font face=\"Arial\" color=\"#000080\" size=\"+0\">" + "<span style=\"font-size:8pt\"><b>" + username + ", " + new Date()
                + ":</b></span></font>" + "<font face=\"Arial\"><span style=\"font-size:8pt\"><p>" + comment.replaceAll("[\n\r]+", "</p><p>")
                + "</p></span></font></div></body></html>";
    }

    private String getTdProtocol() {
        return isSecure ? "tds" : "td";
    }

    private String getChangesetDateFromRevision(String revision
            , final CloseableHttpClient client, final HttpClientContext hcc
            , String domainName, String projectName) {

        if (revision == null) {
            return null;
        }

        try {
            final URI uri = new URIBuilder(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/changesets")
                    .addParameter("page-size", "1")
                    .addParameter("query", "{changeset-file.revision['" + revision + "']}").build();

            HttpGet query = new HttpGet(uri);
            query.addHeader("Accept", "application/xml");

            Response response = runQueryInContext(client, hcc, query);
            int httpReturnCode = response.getResponseStatus();
            String resBody = response.getResponseBody();

            Document doc = response.getDocument();
            final XPath xpath = xpathFactory.newXPath();
            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:
                    final String timestamp = (String) xpath.compile("/Entities/Entity/Fields/Field[@Name='date']/Value/text()")
                            .evaluate(doc, XPathConstants.STRING);
                    if (timestamp == null || timestamp.length() == 0) {
                        throw new BugTrackerException("Could not query revisions from ALM. Revision '" + revision
                                + "' does not correspond to a changeset-file revision");
                    }
                    return timestamp;
                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + httpReturnCode + "; Response: " + resBody);
                    throw new BugTrackerException("Could not query changesets from the ALM server", nested);
            }

        } catch (final Exception e) {
            throw new RuntimeException(e);
        }

    }

    private String massageBugDescription(String bugDescription, List<String> candidateChangesets) {

        if (candidateChangesets != null && candidateChangesets.size() > 0) {
            return bugDescription + "\n" + "This issue could have been introduced in one of the following ALM changesets: " + candidateChangesets;
        }
        return bugDescription;

    }

    private String getAttributeNameForEntity(String entity, String attributeLabel, String domainName, String projectName
            , final CloseableHttpClient client, final HttpClientContext hcc) {

        try {
            HttpGet query = new HttpGet(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/customization/entities/" + entity
                    + "/fields");
            query.addHeader("Accept", "application/xml");

            Response response = runQueryInContext(client, hcc, query);
            int httpReturnCode = response.getResponseStatus();
            String resBody = response.getResponseBody();

            Document doc = response.getDocument();
            final XPath xpath = xpathFactory.newXPath();
            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:
                    return (String) xpath.compile("/Fields/Field[@Label='" + attributeLabel + "']/@Name").evaluate(doc, XPathConstants.STRING);

                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + httpReturnCode + "; Response: " + resBody);
                    throw new BugTrackerException("Could not query attributes for entities from the ALM server", nested);
            }
        } catch (XPathException e) {
            throw new RuntimeException(e);
        }
    }

    private void validateAlmDomainAndProject(String domainName, String projectName
            , final CloseableHttpClient client, final HttpClientContext hcc) throws URISyntaxException {

        final URI uri = new URIBuilder(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/defects").addParameter("page-size", "1").build();
        final HttpGet query = new HttpGet(uri);
        query.addHeader("Accept", "application/xml");

        Response resp = runQueryInContext(client, hcc, query);
        int httpReturnCode = resp.getResponseStatus();
        String response = resp.getResponseBody();

        switch (httpReturnCode) {
            case HttpURLConnection.HTTP_OK:
                return;
            case HttpURLConnection.HTTP_INTERNAL_ERROR:
            case HttpURLConnection.HTTP_NOT_FOUND:
                final String message = MessageFormat.format("The ALM domain {0} and project {1} combination is invalid. "
                        + "Please verify your ALM installation and use the right values.", domainName, projectName);
                throw new BugTrackerException(message);
            default:
                RuntimeException nested = new RuntimeException("Got HTTP return code: " + httpReturnCode + "; Response: " + response);
                throw new BugTrackerException("Could not validate ALM domain and project", nested);

        }
    }

    private List<String> getDomains(final CloseableHttpClient client, final HttpClientContext hcc) {
        try {
            final HttpGet query = new HttpGet(almUrlPrefix + "/qcbin/rest/domains");
            query.addHeader("Accept", "application/xml");

            Response resp = runQueryInContext(client, hcc, query);
            int httpReturnCode = resp.getResponseStatus();
            String response = resp.getResponseBody();

            Document doc = resp.getDocument();
            final XPath xpath = xpathFactory.newXPath();
            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:
                    final List<String> domains = new ArrayList<>();
                    final NodeList nodes = (NodeList) xpath.compile("/Domains/Domain/@Name").evaluate(doc, XPathConstants.NODESET);
                    for (int i = 0; i < nodes.getLength(); i++) {
                        domains.add(nodes.item(i).getTextContent());
                    }
                    return domains;

                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + httpReturnCode + "; Response: " + response);
                    throw new BugTrackerException("Could not query domains from ALM", nested);
            }
        } catch (XPathException e) {
            throw new RuntimeException(e);
        }
    }

    private List<String> getProjects(IssueDetail issueDetail
            , final CloseableHttpClient client, final HttpClientContext hcc, String domain) {

        try {
            final HttpGet query = new HttpGet(almUrlPrefix + "/qcbin/rest/domains/" + domain + "/projects");
            query.addHeader("Accept", "application/xml");

            Response resp = runQueryInContext(client, hcc, query);
            int httpReturnCode = resp.getResponseStatus();
            String response = resp.getResponseBody();

            Document doc = resp.getDocument();
            final XPath xpath = xpathFactory.newXPath();
            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:
                    final List<String> domains = new ArrayList<>();
                    final NodeList nodes = (NodeList) xpath.compile("/Projects/Project/@Name").evaluate(doc, XPathConstants.NODESET);
                    for (int i = 0; i < nodes.getLength(); i++) {
                        domains.add(nodes.item(i).getTextContent());
                    }

                    ArrayList<String> projects = new ArrayList<>();
                    for (String project : domains) {
                        List<BugParam> res = null;
                        try {
                            res = queryBugParameters(issueDetail, domain, project, client, hcc);
                        } catch (Exception e) {
                            LOG.warn(e);
                        } // If we cannot load bug params, disable project.
                        if (res != null) {
                            projects.add(project);
                        }
                    }

                    return projects;

                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + httpReturnCode + "; Response: " + response);
                    throw new BugTrackerException("Could not query projects from ALM", nested);
            }
        } catch (XPathException e) {
            throw new RuntimeException(e);
        }
    }

    private String sendAttachment(final CloseableHttpClient client, final HttpClientContext hcc
                                  , String entityUrl, byte[] fileData, String contentType, String filename, String description
                    ) throws UnsupportedEncodingException {

        final HttpPost sendAttachmentRequest = new HttpPost(entityUrl + "/attachments");

		/* Following code is adapted from the ALM REST API attachment example */

        // This can be pretty much any string - it's used to signify the different mime parts
        String boundary = "exampleboundary";
        // Template to use when sending field data (assuming non-binary data)
        String fieldTemplate = "--%1$s\r\n" + "Content-Disposition: form-data; name=\"%2$s\" \r\n\r\n" + "%3$s" + "\r\n";
        // Template to use when sending file data (binary data still needs to be suffixed)
        String fileDataPrefixTemplate = "--%1$s\r\n" + "Content-Disposition: form-data; name=\"%2$s\"; filename=\"%3$s\"\r\n" + "Content-Type: %4$s\r\n\r\n";
        String filenameData = String.format(fieldTemplate, boundary, "filename", filename);
        String descriptionData = String.format(fieldTemplate, boundary, "description", description);
        String fileDataSuffix = "\r\n--" + boundary + "--";
        String fileDataPrefix = String.format(fileDataPrefixTemplate, boundary, "file", filename, contentType);
        // The order is extremely important: The filename and description come before file data. The name of the file in the file part and in the filename part
        // value MUST MATCH.
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try {
            bytes.write(filenameData.getBytes());
            bytes.write(descriptionData.getBytes());
            bytes.write(fileDataPrefix.getBytes());
            bytes.write(fileData);
            bytes.write(fileDataSuffix.getBytes());
            bytes.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


        final HttpEntity multipartEntity = MultipartEntityBuilder.create().addPart("entity.attachment", new StringBody(bytes.toString(), ContentType.TEXT_PLAIN)).build();
        sendAttachmentRequest.setEntity(multipartEntity);
        sendAttachmentRequest.setHeader("Content-Type", "multipart/form-data; boundary=" + boundary);

        Response sendAttachmentResponse = runQueryInContext(client, hcc, sendAttachmentRequest);
        switch (sendAttachmentResponse.getResponseStatus()) {
            case HttpURLConnection.HTTP_CREATED:
                return sendAttachmentResponse.getLocation();

            default:
                RuntimeException nested = new RuntimeException("Got HTTP return code: " + sendAttachmentResponse.getResponseStatus() + "; Response: " + sendAttachmentResponse.getResponseBody());
                throw new BugTrackerException("Could not attach file to entity", nested);
        }
    }

    @Override
    public List<BugParam> getBatchBugParameters(UserAuthenticationStore credentials) {
        return getBugParameters(null, credentials);
    }

    @Override
    public List<BugParam> onBatchBugParameterChange(String changedParamIdentifier, List<BugParam> currentValues, UserAuthenticationStore credentials) {
        return onParameterChange(null, changedParamIdentifier, currentValues, credentials);
    }

    private String constructMultiIssueDefectXmlString(MultiIssueBugSubmission bug, String detectedInBuildInstanceId, List<String> candidateChangesets,
                                                      String detectedByUser, String categoryAttributeName) throws JAXBException {

        final Entity defect = new Entity();
        defect.setType(DEFECT_ENTITY_TYPE_NAME);
        final Entity.Fields fields = new Entity.Fields();
        defect.setFields(fields);

        fields.getField().add(buildEntityField(DETECTED_BY_FIELD_NAME, detectedByUser, DEFAULT_TRIM_LENGTH));

        fields.getField().add(buildEntityField(CREATION_TIME_FIELD_NAME, new SimpleDateFormat("yyyy-MM-dd").format(new Date()), DEFAULT_TRIM_LENGTH));

        if (categoryAttributeName != null && categoryAttributeName.length() != 0) {
            String analysisType = bug.getIssueDetails().get(0).getAnalysisType();
            boolean allSame = true;
            for (IssueDetail issueDetail : bug.getIssueDetails()) {
                if (!analysisType.equals(issueDetail.getAnalysisType())) {
                    allSame = false;
                    break;
                }
            }
            if (allSame) {
                fields.getField().add(buildEntityField(categoryAttributeName, "Fortify - " + analysisType, DEFAULT_TRIM_LENGTH));
            }
        }

        fields.getField().add(buildEntityField(NAME_FIELD_NAME
                , anyNotNull(bug.getParams().get(SUMMARY_PARAM_NAME), bug.getParams().get(NAME_PARAM_NAME)), DEFAULT_TRIM_LENGTH));

        if (detectedInBuildInstanceId != null && detectedInBuildInstanceId.length() != 0) {
            fields.getField().add(buildEntityField(DETECTED_IN_BUILD_FIELD_NAME, detectedInBuildInstanceId, DEFAULT_TRIM_LENGTH));
        }

        if (candidateChangesets != null && candidateChangesets.size() == 1) {
            fields.getField().add(buildEntityField(CAUSED_BY_CHANGESET_FIELD_NAME, candidateChangesets.get(0), DEFAULT_TRIM_LENGTH));
        }

        fields.getField().add(buildEntityField(DESCRIPTION_FIELD_NAME
                , convertToHtml(massageBugDescription(bug.getParams().get(DESCRIPTION_PARAM_NAME), candidateChangesets)), DEFAULT_DESCRIPTION_TRIM_LENGTH));

        if (bug.getIssueDetails().size() == 1) {
            // Would it make sense to just include all comments from all issues?
            final StringBuilder allComments = new StringBuilder();
            for (final IssueComment c : bug.getIssueDetails().get(0).getComments()) {
                allComments.append("[").append(c.getUsername()).append(" on ").append(c.getTimestamp()).append("]: ").append(c.getBody());
                allComments.append("\n\n");
            }
            fields.getField().add(buildEntityField(DEV_COMMENTS_FIELD_NAME, convertToHtml(allComments.toString()), DEFAULT_COMMENTS_TRIM_LENGTH));
        }

        fields.getField().add(buildEntityField(SEVERITY_FIELD_NAME, bug.getParams().get(SEVERITY_PARAM_NAME), DEFAULT_TRIM_LENGTH));

        for (String paramName : bug.getParams().keySet()) {
            if (!(paramName.equals(NAME_PARAM_NAME) || paramName.equals(DESCRIPTION_PARAM_NAME) ||
                    paramName.equals(PROJECT_PARAM_NAME) || paramName.equals(DOMAIN_PARAM_NAME)
                    || paramName.equals(SEVERITY_PARAM_NAME))) {
                fields.getField().add(buildEntityField(paramName, bug.getParams().get(paramName), DEFAULT_TRIM_LENGTH));
            }
        }

        final String defectXmlString = EntityMarshallingUtils.marshal(Entity.class, defect);
        LOG.debug(String.format("defectXmlString: %s", defectXmlString));
        return defectXmlString;
    }


    private Entity.Fields.Field buildEntityField (final String fieldName, final String elementValue, final int trimLength ) {
        Entity.Fields.Field field = new Entity.Fields.Field();
        field.setName(fieldName);
        field.getValue().add(trimStringFieldValue(elementValue, trimLength));
        return field;
    }

    private String trimStringFieldValue(String val, int trimLength) {

        if (trimLength > ELLIPSIS_LEN) {
            if ((null != val) && val.length() > trimLength) {
                return val.substring(0, trimLength-ELLIPSIS_LEN) + ELLIPSIS;
            }
        } else if (trimLength > TRIM_LENGTH_UNLIMITED) {
            throw new IllegalArgumentException("trimLength between 0 and "+ELLIPSIS_LEN+" is not acceptable: "+ trimLength);
        }

        return val;
    }

    private String anyNotNull(String... strings) {
        for (String str : strings) {
            if (str != null) {
                return str;
            }
        }
        return null;
    }

    @Override
    public Bug fileMultiIssueBug(MultiIssueBugSubmission bugSubmission, UserAuthenticationStore credentials) {

        Bug bug = null;
        final HttpClientContext hcc = createHttpClientContext();
        stopLock.startRequest();
        try (CloseableHttpClient client = authenticate(credentials.getUserName(), credentials.getPassword(), hcc)) {

            final String domainName = bugSubmission.getParams().get(DOMAIN_PARAM_NAME);
            final String projectName = bugSubmission.getParams().get(PROJECT_PARAM_NAME);

            validateAlmDomainAndProject(domainName, projectName, client, hcc);

            String detectedInBuildInstance = null;
            if (bugSubmission.getIssueDetails().size() == 1) {
                IssueDetail issueDetail = bugSubmission.getIssueDetails().get(0);
                if (issueDetail.getDetectedInBuild() != null) {
                    try {
                        detectedInBuildInstance = getBuildInstanceIdFromRevision(
                                issueDetail.getDetectedInBuild(), client, hcc, domainName, projectName);
                    } catch (Exception e) {
                        LOG.warn("Skipping identification of build instance where issue was detected.", e);
                    }
                }
            }
            List<String> candidateChangesets = null;
            if (bugSubmission.getIssueDetails().size() > 0) {
                final IssueDetail issueDetail = bugSubmission.getIssueDetails().get(0);
                final Set<String> lastBuildWithoutIssueVals = collectLastBuildWithoutIssue(bugSubmission);
                final Set<String> detectedInBuildVals = collectDetectedInBuild(bugSubmission);
                if (lastBuildWithoutIssueVals.size() > 0 && detectedInBuildVals.size() > 0) {
                    try {
                        String fileName = issueDetail.getFileName();
                        // it's OK to use the file name from the first issue detail since MultiIssueBugSubmission created for one specific file.

                        candidateChangesets = queryChangesetsBetween(lastBuildWithoutIssueVals, detectedInBuildVals, fileName,
                                bugSubmission.getParams(), credentials, hcc);
                    } catch (Exception e) {
                        LOG.warn("Skipping changeset discovery", e);
                    }

                }
            }

            final HttpPost createDefectRequest = new HttpPost(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/defects");
            createDefectRequest.addHeader("Accept", "application/xml");

            final String defectXmlString = constructMultiIssueDefectXmlString(bugSubmission, detectedInBuildInstance, candidateChangesets, credentials.getUserName(),
                    getAttributeNameForEntity(DEFECT_ENTITY_TYPE_NAME, CATEGORY_LABEL_NAME, domainName, projectName, client, hcc));
            createDefectRequest.setEntity(new StringEntity(defectXmlString, ContentType.create("application/xml", "UTF-8")));

            Response createDefectResponse = runQueryInContext(client, hcc, createDefectRequest);
            switch (createDefectResponse.getResponseStatus()) {
                case HttpURLConnection.HTTP_CREATED:
                    final XPath xpath = xpathFactory.newXPath();
                    final String bugId = composeBugId(domainName, projectName, extractBugNumber(xpath, createDefectResponse.getDocument()));
                    final String bugStatus = extractBugStatus(xpath, createDefectResponse.getDocument());
                    final String location = createDefectResponse.getLocation();

                    if (location != null) {
                        uploadBugAttachments(client, hcc, bugSubmission, location);
                    } else {
                        LOG.warn("Could not upload any URL attachment file to defect ('Location' header not found in the response).");
                    }

                    destroyAlmSession(client, hcc);
                    bug = new Bug(bugId, bugStatus);
                    break;
                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + createDefectResponse.getResponseStatus() + "; Response: " + createDefectResponse.getResponseBody());
                    destroyAlmSession(client, hcc);
                    throw new BugTrackerException("Could not create a bug on the ALM server.", nested);
            }
        } catch (IOException e) {
            logClientCloseError(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            stopLock.endRequest();
        }

        return bug;
    }

    private String extractBugStatus(final XPath xpath, final Document context) throws XPathExpressionException {
        return (String) xpath.compile("/Entities/Entity/Fields/Field[@Name='status']/Value/text()").evaluate(context, XPathConstants.STRING);
    }

    private String extractBugNumber(final XPath xpath, final Document context) throws XPathExpressionException {
        return (String) xpath.compile("/Entity/Fields/Field[@Name='id']/Value/text()").evaluate(context, XPathConstants.STRING);
    }

    private String composeBugId(final String domainName, final String projectName, final String bugNumber ) {
        return domainName + ":" + projectName + ":" + bugNumber;
    }

    private void uploadBugAttachments(final CloseableHttpClient client, final HttpClientContext hcc
                                      , final MultiIssueBugSubmission bug, final String entityUrl) throws Exception {

        for (IssueDetail issueDetail : bug.getIssueDetails()) {
            uploadBugAttachment(client, hcc, issueDetail, entityUrl);
        }
    }

    private void uploadBugAttachment(final CloseableHttpClient client, final HttpClientContext hcc
                    , final IssueDetail issueDetail, final String entityUrl) throws Exception {

        try {
            String shortcutFileData = "[InternetShortcut]\r\nURL=" + issueDetail.getIssueDeepLink();
            sendAttachment(client, hcc, entityUrl, shortcutFileData.getBytes()
                    , "text/plain", "issueDeepLink.URL", "Deep Link to Issue in SSC");
        } catch (Exception e) {
            LOG.debug("", e);
            LOG.warn(String.format("Could not upload URL attachment file for issueInstanceId=%s to defect.", issueDetail.getIssueInstanceId()));
            throw new Exception(e);
        }
    }

    private Set<String> collectLastBuildWithoutIssue(MultiIssueBugSubmission bug) {
        final Set<String> result = new LinkedHashSet<>();
        for (final IssueDetail issueDetail : bug.getIssueDetails()) {
            if (issueDetail.getLastBuildWithoutIssue() != null) {
                result.add(issueDetail.getLastBuildWithoutIssue());
            }
        }
        return result;
    }

    private Set<String> collectDetectedInBuild(MultiIssueBugSubmission bug) {
        final Set<String> result = new LinkedHashSet<>();
        for (final IssueDetail issueDetail : bug.getIssueDetails()) {
            if (issueDetail.getDetectedInBuild() != null) {
                result.add(issueDetail.getDetectedInBuild());
            }
        }
        return result;
    }

    @Override
    public boolean isBugOpen(Bug bug, UserAuthenticationStore credentials) {
        return "".equals(bug.getBugStatus()) || STATUS_NEW.equals(bug.getBugStatus()) || STATUS_OPEN.equals(bug.getBugStatus())
                || STATUS_REOPEN.equals(bug.getBugStatus());
    }

    @Override
    public boolean isBugClosed(Bug bug, UserAuthenticationStore credentials) {
        return !isBugOpen(bug, credentials);
    }

    @Override
    public boolean isBugClosedAndCanReOpen(Bug bug, UserAuthenticationStore credentials) {
        return STATUS_CLOSED.equals(bug.getBugStatus()) || STATUS_FIXED.equals(bug.getBugStatus());
    }

    private Entity.Fields.Field createNewCommentField(Bug bug, String addComment
            , UserAuthenticationStore credentials, final HttpClientContext hcc) {

        final Entity.Fields.Field comments = new Entity.Fields.Field();
        comments.setName(DEV_COMMENTS_FIELD_NAME);
        String currentComments = fetchBugComments(bug.getBugId(), credentials, hcc);
        if (currentComments != null && currentComments.trim().length() > 0) {
            comments.getValue().add(currentComments);
        }
        String newComment;
        newComment = convertCommentToHtml(addComment, credentials.getUserName());
        comments.getValue().add(newComment);
        return comments;
    }

    @Override
    public void reOpenBug(Bug bug, String comment, UserAuthenticationStore credentials) {

        if (STATUS_REJECTED.equals(bug.getBugStatus())) {
            throw new BugTrackerException("Bug " + bug.getBugId() + " cannot be reopened.");
        }

        final HttpClientContext hcc = createHttpClientContext();
        try {
            stopLock.startRequest();

            final Entity defect = new Entity();
            defect.setType(DEFECT_ENTITY_TYPE_NAME);
            final Entity.Fields fields = new Entity.Fields();
            defect.setFields(fields);

            final Entity.Fields.Field status = new Entity.Fields.Field();
            status.setName(STATUS_FIELD_NAME);
            status.getValue().add(STATUS_REOPEN);
            fields.getField().add(status);

            fields.getField().add(createNewCommentField(bug, comment, credentials, hcc));
            updateBug(bug, defect, credentials, hcc);
        } finally {
            stopLock.endRequest();
        }
    }

    @Override
    public void addCommentToBug(Bug bug, String comment, UserAuthenticationStore credentials) {

        final HttpClientContext hcc = createHttpClientContext();
        stopLock.startRequest();
        try {
            final Entity defect = new Entity();
            defect.setType(DEFECT_ENTITY_TYPE_NAME);
            final Entity.Fields fields = new Entity.Fields();
            defect.setFields(fields);
            fields.getField().add(createNewCommentField(bug, comment, credentials, hcc));

            updateBug(bug, defect, credentials, hcc);
        } finally {
            stopLock.endRequest();
        }
    }

    private void updateBug(Bug bug, Entity defect, UserAuthenticationStore credentials, final HttpClientContext hcc) {

        String[] splits = bug.getBugId().split(":");
        if (splits.length != 3) {
            throw new BugTrackerException("External bug id does not contain the 3 expected elements.");
        }

        final String domainName = splits[0];
        final String projectName = splits[1];
        final String defectId = splits[2];

        try (CloseableHttpClient client = authenticate(credentials.getUserName(), credentials.getPassword(), hcc)) {

            validateAlmDomainAndProject(domainName, projectName, client, hcc);
            final HttpPut updateDefectRequest = new HttpPut(almUrlPrefix + "/qcbin/rest/domains/" + domainName + "/projects/" + projectName + "/defects" + "/" + defectId);
            updateDefectRequest.addHeader("Accept", "application/xml");

            updateDefectRequest.setEntity(new StringEntity(EntityMarshallingUtils.marshal(Entity.class, defect), ContentType.create("application/xml", CHARSET_UTF8)));

            Response resp = runQueryInContext(client, hcc, updateDefectRequest);
            int httpReturnCode = resp.getResponseStatus();
            String response = resp.getResponseBody();
            destroyAlmSession(client, hcc);

            switch (httpReturnCode) {
                case HttpURLConnection.HTTP_OK:
                    return;
                default:
                    RuntimeException nested = new RuntimeException("Got HTTP return code: " + httpReturnCode + "; Response: " + response);
                    throw new BugTrackerException("Could not update a bug on the ALM server.", nested);
            }
        } catch (IOException e) {
            logClientCloseError(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private InputSource makeInputSource(final InputStream inputStream) throws UnsupportedEncodingException {
        Reader reader = new InputStreamReader(inputStream, "UTF-8");
        InputSource result = new InputSource(reader);
        result.setEncoding("UTF-8");
        return result;
    }

    private void logClientCloseError (IOException e) {
        LOG.warn("Unable to close HTTP client");
        if (LOG.isDebugEnabled()) {
            LOG.debug(e);
        }
    }

}
