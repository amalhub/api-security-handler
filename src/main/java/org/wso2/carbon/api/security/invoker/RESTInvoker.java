/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.api.security.invoker;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.api.security.utils.AuthConstants;
import org.wso2.carbon.utils.CarbonUtils;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public class RESTInvoker {

    private static final Log log = LogFactory.getLog(RESTInvoker.class);

    private int maxTotalConnections;
    private int maxTotalConnectionsPerRoute;
    private int connectionTimeout;
    private int socketTimeout;

    private CloseableHttpClient client = null;
    private PoolingHttpClientConnectionManager connectionManager = null;

    public RESTInvoker() {
        configureHttpClient();
    }

    private void parseConfiguration() {
        String carbonConfigDirPath = CarbonUtils.getCarbonConfigDirPath();
        String activitiConfigPath = carbonConfigDirPath + File.separator +
                AuthConstants.AUTH_CONFIGURATION_FILE_NAME;
        File configFile = new File(activitiConfigPath);

        try {
            String configContent = FileUtils.readFileToString(configFile);
            OMElement configElement = AXIOMUtil.stringToOM(configContent);
            Iterator beans = configElement.getChildrenWithName(
                    new QName("http://www.springframework.org/schema/beans", "bean"));

            while (beans.hasNext()) {
                OMElement bean = (OMElement) beans.next();
                String beanId = bean.getAttributeValue(new QName(null, "id"));
                if (beanId.equals(RESTConstants.REST_CLIENT_CONFIG_ELEMENT)) {
                    Iterator beanProps = bean.getChildrenWithName(
                            new QName("http://www.springframework.org/schema/beans", "property"));

                    while (beanProps.hasNext()) {
                        OMElement beanProp = (OMElement) beanProps.next();
                        String beanName = beanProp.getAttributeValue(new QName(null, "name"));
                        if (RESTConstants.REST_CLIENT_MAX_TOTAL_CONNECTIONS.equals(beanName)) {
                            String value = beanProp.getAttributeValue(new QName(null, "value"));
                            if (value != null && !value.trim().equals("")) {
                                maxTotalConnections = Integer.parseInt(value);
                            }
                            if (log.isDebugEnabled()) {
                                log.debug("Max total http connections " + maxTotalConnections);
                            }
                        } else if (RESTConstants.REST_CLIENT_MAX_CONNECTIONS_PER_ROUTE.equals(beanName)) {
                            String value = beanProp.getAttributeValue(new QName(null, "value"));
                            if (value != null && !value.trim().equals("")) {
                                maxTotalConnectionsPerRoute = Integer.parseInt(value);
                            }
                            if (log.isDebugEnabled()) {
                                log.debug("Max total client connections per route " + maxTotalConnectionsPerRoute);
                            }
                        } else if (RESTConstants.REST_CLEINT_CONNECTION_TIMEOUT.equals(beanName)) {
                            String value = beanProp.getAttributeValue(new QName(null, "value"));
                            if (value != null && !value.trim().equals("")) {
                                connectionTimeout = Integer.parseInt(value);
                            }
                        } else if (RESTConstants.REST_CLEINT_SOCKET_TIMEOUT.equals(beanName)) {
                            String value = beanProp.getAttributeValue(new QName(null, "value"));
                            if (value != null && !value.trim().equals("")) {
                                socketTimeout = Integer.parseInt(value);
                            }
                        }
                    }
                }
            }
        } catch (IOException | XMLStreamException e) {
            log.error("Error in processing http connection settings, using default settings", e);
        }


    }

    private void configureHttpClient() {

        parseConfiguration();

        RequestConfig defaultRequestConfig = RequestConfig.custom()
                .setExpectContinueEnabled(true)
                .setConnectTimeout(connectionTimeout)
                .setSocketTimeout(socketTimeout)
                .build();

        connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setDefaultMaxPerRoute(maxTotalConnectionsPerRoute);
        connectionManager.setMaxTotal(maxTotalConnections);
        client = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(defaultRequestConfig)
                .build();

        if (log.isDebugEnabled()) {
            log.debug("REST client initialized with" +
                    "maxTotalConnection = " + maxTotalConnections +
                    "maxConnectionsPerRoute = " + maxTotalConnectionsPerRoute +
                    "connectionTimeout = " + connectionTimeout);
        }
    }

    public void closeHttpClient() {
        IOUtils.closeQuietly(client);
        IOUtils.closeQuietly(connectionManager);
    }

    public RESTResponse invokePOST(URI uri, BasicNameValuePair[] jsonHeaders, String username,
                                   String password, String payload) throws IOException {

        HttpPost httpPost = null;
        CloseableHttpResponse response = null;
        Header[] headers;
        int httpStatus;
        String contentType;
        String output;
        try {
            httpPost = new HttpPost(uri);
            httpPost.setEntity(new StringEntity(payload));
            for (BasicNameValuePair header: jsonHeaders) {
                httpPost.setHeader(header.getName(), header.getValue());
            }
            response = sendReceiveRequest(httpPost, username, password);
            output = IOUtils.toString(response.getEntity().getContent());
            headers = response.getAllHeaders();
            httpStatus = response.getStatusLine().getStatusCode();
            contentType = response.getEntity().getContentType().getValue();
            if (log.isTraceEnabled()) {
                log.trace("Invoked POST " + uri.toString() +
                        " - Input payload: " + payload + " - Response message: " + output);
            }
            EntityUtils.consume(response.getEntity());
        } finally {
            if (response != null) {
                IOUtils.closeQuietly(response);
            }
            if (httpPost != null) {
                httpPost.releaseConnection();
            }
        }
        return new RESTResponse(contentType, output, headers, httpStatus);
    }

    private CloseableHttpResponse sendReceiveRequest(HttpRequestBase requestBase, String username, String password)
            throws IOException {
        CloseableHttpResponse response;
        if (username != null && !username.equals("") && password != null) {
            String combinedCredentials = username + ":" + password;
            byte[] encodedCredentials = Base64.encodeBase64(combinedCredentials.getBytes(StandardCharsets.UTF_8));
            requestBase.addHeader("Authorization", "Basic " + new String(encodedCredentials));

            response = client.execute(requestBase);
        } else {
            response = client.execute(requestBase);
        }
        return response;
    }
}
