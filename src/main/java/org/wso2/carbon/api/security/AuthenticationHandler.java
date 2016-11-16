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
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.wso2.carbon.api.security.utils.AuthConstants;
import org.wso2.carbon.api.security.utils.CoreUtils;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.List;

public class AuthenticationHandler implements Handler {
    private static final Log log = LogFactory.getLog(AuthenticationHandler.class);
    private static HandlerDescription EMPTY_HANDLER_METADATA = new HandlerDescription("API Security Handler");
    private HandlerDescription handlerDesc;
    private ArrayList<String> apiList = new ArrayList<String>();

    public AuthenticationHandler() {
        log.info("Engaging API Security Handler");
        this.handlerDesc = EMPTY_HANDLER_METADATA;
        apiList.add("/services/echo");
    }

    public void cleanup() {
    }

    public void init(HandlerDescription handlerDescription) {
        this.handlerDesc = handlerDescription;
    }

    public InvocationResponse invoke(MessageContext messageContext) throws AxisFault {
        CoreUtils.debugLog(log, "Authentication handler invoked.");
        String ctxPath = messageContext.getTo().getAddress().trim();
        CoreUtils.debugLog(log, "Authentication handler invoked by: ", ctxPath);

        if (isSecuredAPI(ctxPath)) {

            Object sslCertObject = messageContext.getProperty(AuthConstants.SSL_CERT_X509);

            if (sslCertObject != null) {
                StringBuilder dns = new StringBuilder();
                try {
                    javax.security.cert.X509Certificate[] certs = (javax.security.cert.X509Certificate[]) sslCertObject;

                    for (javax.security.cert.X509Certificate aCert : certs) {
                        dns.append(aCert.getSubjectDN().getName()).append(", ");
                    }
                    CoreUtils.debugLog(log, "Following SSL Certificates were found: ", dns.toString());
                    return InvocationResponse.CONTINUE;

                } catch (Exception e) {
                    log.error("Error while processing certificate DNS. :  " + dns.toString(), e);
                    setFaultCodeAndThrowAxisFault(messageContext, e);
                    return InvocationResponse.SUSPEND;
                }
            } else {
                setFaultCodeAndThrowAxisFault(messageContext, new Exception("SSL required"));
                return InvocationResponse.SUSPEND;
            }
        } else {
            return InvocationResponse.CONTINUE;
        }

    }

    private boolean isSecuredAPI(String contextPath) {
        for (String path: apiList) {
            if (contextPath.contains(path)) {
                return true;
            }
        }
        return false;
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
}
