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
package org.wso2.carbon.api.security.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.certificate.mgt.core.scep.SCEPManager;
import org.wso2.carbon.certificate.mgt.core.service.CertificateManagementService;

/**
 * @scr.component name="org.wso2.carbon.api.security" immediate="true"
 * @scr.reference name="org.wso2.carbon.certificate.mgt.core.scep"
 * interface="org.wso2.carbon.certificate.mgt.core.scep.SCEPManager"
 * policy="dynamic"
 * cardinality="1..n"
 * bind="setSCEPManagementService"
 * unbind="unsetSCEPManagementService"
 * @scr.reference name="org.wso2.carbon.certificate.mgt"
 * interface="org.wso2.carbon.certificate.mgt.core.service.CertificateManagementService"
 * policy="dynamic"
 * cardinality="1..n"
 * bind="setCertificateManagementService"
 * unbind="unsetCertificateManagementService"
 */
public class APISecurityServiceComponent {
    private static final Log log = LogFactory.getLog(APISecurityServiceComponent.class);

    @SuppressWarnings("unused")
    protected void activate(ComponentContext componentContext) {

    }

    @SuppressWarnings("unused")
    protected void deactivate(ComponentContext componentContext) {
        //do nothing
    }

    protected void setSCEPManagementService(SCEPManager scepManager) {
        if (log.isDebugEnabled()) {
            log.debug("Setting SCEP management service");
        }
        APISecurityDataHolder.getInstance().setScepManager(scepManager);
    }

    protected void unsetSCEPManagementService(SCEPManager scepManager) {
        if (log.isDebugEnabled()) {
            log.debug("Removing SCEP management service");
        }

        APISecurityDataHolder.getInstance().setScepManager(null);
    }

    protected void setCertificateManagementService(CertificateManagementService certificateManagementService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting certificate management service");
        }
        APISecurityDataHolder.getInstance().setCertificateManagementService(certificateManagementService);
    }

    protected void unsetCertificateManagementService(CertificateManagementService certificateManagementService) {
        if (log.isDebugEnabled()) {
            log.debug("Removing certificate management service");
        }

        APISecurityDataHolder.getInstance().setCertificateManagementService(null);
    }
}
