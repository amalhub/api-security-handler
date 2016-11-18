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

import org.wso2.carbon.certificate.mgt.core.scep.SCEPManager;
import org.wso2.carbon.certificate.mgt.core.service.CertificateManagementService;

public class APISecurityDataHolder {
    private SCEPManager scepManager;
    private CertificateManagementService certificateManagementService;

    private static APISecurityDataHolder
            thisInstance = new APISecurityDataHolder();

    private APISecurityDataHolder() {}

    public static APISecurityDataHolder getInstance() {
        return thisInstance;
    }

    public SCEPManager getScepManager() {
        if (scepManager == null) {
            throw new IllegalStateException("SCEPManager service is not initialized properly");
        }
        return scepManager;
    }

    public void setScepManager(SCEPManager scepManager) {
        this.scepManager = scepManager;
    }

    public CertificateManagementService getCertificateManagementService() {
        if (certificateManagementService == null) {
            throw new IllegalStateException("CertificateManagement service is not initialized properly");
        }
        return certificateManagementService;
    }

    public void setCertificateManagementService(CertificateManagementService certificateManagementService) {
        this.certificateManagementService = certificateManagementService;
    }

}
