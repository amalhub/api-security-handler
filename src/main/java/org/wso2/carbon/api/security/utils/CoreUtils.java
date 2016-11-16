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
package org.wso2.carbon.api.security.utils;

import org.apache.commons.logging.Log;

public class CoreUtils {

    /**
     * Universal debug log function
     *
     * @param logger Log object specific to the class
     * @param message initial debug log message
     * @param vars optional strings to be appended for the log
     */
    public static void debugLog(Log logger, String message, Object ... vars) {
        if(logger.isDebugEnabled()) {
            if (vars.length < 1) {
                logger.debug(message);
                return;
            }
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(message);
            for (Object var : vars) {
                stringBuilder.append(var.toString());
            }
            logger.debug(stringBuilder.toString());
        }
    }
}
