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
package org.wso2.carbon.api.security;

import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAP12Constants;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.HandlerDescription;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.engine.Handler;
import org.apache.axis2.namespace.Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.message.BasicNameValuePair;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.Base64;
import org.json.JSONObject;
import org.wso2.carbon.api.security.invoker.RESTInvoker;
import org.wso2.carbon.api.security.invoker.RESTResponse;
import org.wso2.carbon.api.security.utils.AuthConstants;
import org.wso2.carbon.api.security.utils.CoreUtils;

import javax.security.cert.X509Certificate;
import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class AuthenticationHandler implements Handler {
    private static final Log log = LogFactory.getLog(AuthenticationHandler.class);
    private static HandlerDescription EMPTY_HANDLER_METADATA = new HandlerDescription("API Security Handler");
    private HandlerDescription handlerDesc;
    private ArrayList<String> apiList;
    private RESTInvoker restInvoker;

    /**
     * Setting up configurations at the constructor
     */
    public AuthenticationHandler() {
        log.info("Engaging API Security Handler");
        apiList = CoreUtils.readApiFilterList();
        restInvoker = new RESTInvoker();
        this.handlerDesc = EMPTY_HANDLER_METADATA;
    }

    /**
     * Handles incoming http/s requests
     *
     * @param messageContext
     * @return response
     * @throws AxisFault
     */
    public InvocationResponse invoke(MessageContext messageContext) throws AxisFault {
        CoreUtils.debugLog(log, "Authentication handler invoked.");
        String ctxPath = messageContext.getTo().getAddress().trim();
        CoreUtils.debugLog(log, "Authentication handler invoked by: ", ctxPath);

        if (isSecuredAPI(messageContext)) {

            Object sslCertObject = messageContext.getProperty(AuthConstants.SSL_CERT_X509);

            if (sslCertObject != null) {
                StringBuilder dns = new StringBuilder();
                try {
                    X509Certificate[] certs = (X509Certificate[]) sslCertObject;

                    for (X509Certificate aCert : certs) {
                        dns.append(aCert.getSubjectDN().getName()).append(", ");
                    }
                    CoreUtils.debugLog(log, "Following SSL Certificates were found: ", dns.toString());
                    StringBuilder cert = new StringBuilder();
                    cert.append(Base64.encode(certs[0].getEncoded()));

                    CoreUtils.debugLog(log, "Verify Cert:\n", cert.toString());

                    URI dcrUrl = new URI(AuthConstants.HTTPS + "://" + CoreUtils.getHost() + ":" + CoreUtils
                            .getHttpsPort() + "/dynamic-client-web/register");
                    String dcrContent = "{\n" +
                            "\"owner\":\"" + CoreUtils.getUsername() + "\",\n" +
                            "\"clientName\":\"emm\",\n" +
                            "\"grantType\":\"refresh_token password client_credentials\",\n" +
                            "\"tokenScope\":\"default\"\n" +
                            "}";
                    BasicNameValuePair drcHeaders[] = {new BasicNameValuePair("Content-Type", "application/json")};

                    RESTResponse response = restInvoker.invokePOST(dcrUrl, drcHeaders, null,
                            null, dcrContent);
                    CoreUtils.debugLog(log, "DCR response:", response.getContent());
                    JSONObject jsonResponse = new JSONObject(response.getContent());
                    String clientId = jsonResponse.getString("client_id");
                    String clientSecret = jsonResponse.getString("client_secret");

                    URI tokenUrl = new URI(AuthConstants.HTTPS + "://" + CoreUtils.getHost() + ":" + CoreUtils
                            .getHttpsPort() + "/oauth2/token");
                    String tokenContent = "grant_type=password&username=" + CoreUtils.getUsername() + "&password=" +
                            CoreUtils.getPassword() + "&scope=activity-view";
                    String tokenBasicAuth = "Basic " + Base64.encode((clientId + ":" + clientSecret).getBytes());
                    BasicNameValuePair tokenHeaders[] = {new BasicNameValuePair("Authorization", tokenBasicAuth), new
                            BasicNameValuePair("Content-Type", "application/x-www-form-urlencoded")};

                    response = restInvoker.invokePOST(tokenUrl, tokenHeaders, null,
                            null, tokenContent);
                    CoreUtils.debugLog(log, "Token response:", response.getContent());
                    jsonResponse = new JSONObject(response.getContent());
                    String accessToken = jsonResponse.getString("access_token");

                    URI certVerifyUrl = new URI(AuthConstants.HTTPS + "://" + CoreUtils.getHost() + ":" + CoreUtils
                            .getHttpsPort() + "/api/certificate-mgt/v1.0/admin/certificates" + "/verify");
                    BasicNameValuePair certVerifyHeaders[] = {new BasicNameValuePair("Authorization", "Bearer " +
                            accessToken), new BasicNameValuePair("Content-Type", "application/json")};
                    String certVerifyContent = "{\n" +
                            "\"pem\":\"" + cert.toString() + "\",\n" +
                            "\"tenantId\": \"-1234\",\n" +
                            "\"serial\":\"\"\n" +
                            "}";

                    response = restInvoker.invokePOST(certVerifyUrl, certVerifyHeaders, null,
                            null, certVerifyContent);
                    CoreUtils.debugLog(log, "Verify response:", response.getContent());

                    if (!response.getContent().contains("invalid")) {
                        return InvocationResponse.CONTINUE;
                    }
                    log.warn("Unauthorized request for api: " + ctxPath);
                    setFaultCodeAndThrowAxisFault(messageContext, new Exception("Unauthorized!"));
                    return InvocationResponse.SUSPEND;

                } catch (Exception e) {
                    log.error("Error while processing certificate DNS. :  " + dns.toString(), e);
                    setFaultCodeAndThrowAxisFault(messageContext, e);
                    return InvocationResponse.SUSPEND;
                }
            } else {
                log.warn("Unauthorized request for api: " + ctxPath);
                setFaultCodeAndThrowAxisFault(messageContext, new Exception("SSL required"));
                return InvocationResponse.SUSPEND;
            }
        } else {
            return InvocationResponse.CONTINUE;
        }

    }

    /**
     * API filter
     * @param messageContext
     * @return boolean
     */
    private boolean isSecuredAPI(MessageContext messageContext) {
        if (messageContext.getTransportIn().getName().toLowerCase().equals(AuthConstants.HTTPS)) {
            for (String path: apiList) {
                if (messageContext.getTo().getAddress().trim().contains(path)) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    /**
     * Convert javax.security to java.security
     * @param certificate
     * @return java.security.cert.X509Certificate
     */
    public static java.security.cert.X509Certificate convert(javax.security.cert.X509Certificate certificate) {
        try {
            byte[] encoded = certificate.getEncoded();
            ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
            java.security.cert.CertificateFactory cf
                    = java.security.cert.CertificateFactory.getInstance("X.509");
            return (java.security.cert.X509Certificate)cf.generateCertificate(bis);
        } catch (java.security.cert.CertificateEncodingException e) {
        } catch (javax.security.cert.CertificateEncodingException e) {
        } catch (java.security.cert.CertificateException e) {
        }
        return null;
    }

    private void setFaultCodeAndThrowAxisFault(MessageContext msgContext, Exception e) throws AxisFault {

        msgContext.setProperty(AuthConstants.SEC_FAULT, Boolean.TRUE);
        String soapVersionURI =  msgContext.getEnvelope().getNamespace().getNamespaceURI();
        QName faultCode = null;
        /*
         * Get the faultCode from the thrown WSSecurity exception, if there is one
         */
        if (e instanceof WSSecurityException)
        {
            faultCode = ((WSSecurityException)e).getFaultCode();
        }
        /*
         * Otherwise default to InvalidSecurity
         */
        if (faultCode == null)
        {
            faultCode = new QName(WSConstants.INVALID_SECURITY.getNamespaceURI(),
                    WSConstants.INVALID_SECURITY.getLocalPart(), AuthConstants.WSSE);
        }

        if (soapVersionURI.equals(SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI) ) {

            throw new AxisFault(faultCode,e.getMessage(),e);

        } else if (soapVersionURI.equals(SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI)) {

            List subfaultCodes = new ArrayList();
            subfaultCodes.add(faultCode);
            throw new AxisFault(Constants.FAULT_SOAP12_SENDER,subfaultCodes,e.getMessage(),e);

        }

    }

    public void cleanup() {
    }

    public void init(HandlerDescription handlerDescription) {
        this.handlerDesc = handlerDescription;
    }

    public void flowComplete(org.apache.axis2.context.MessageContext messageContext) {
    }

    public HandlerDescription getHandlerDesc() {
        return this.handlerDesc;
    }

    public String getName() {
        return "API security inflow handler";
    }

    public Parameter getParameter(String name) {
        return this.handlerDesc.getParameter(name);
    }
}
