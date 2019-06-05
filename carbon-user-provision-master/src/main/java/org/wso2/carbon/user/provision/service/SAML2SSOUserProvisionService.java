/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.user.provision.service;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mozilla.javascript.NativeObject;
import org.wso2.carbon.user.provision.SAML2SSOUserProvisioner;
import org.wso2.carbon.user.provision.SAML2SSOUserProvisionerImpl;
import org.wso2.carbon.user.provision.common.Constants;
import org.wso2.carbon.user.provision.common.SAML2SSOUserProvisionException;
import org.wso2.carbon.user.provision.common.Utils;
import org.wso2.carbon.user.provision.internal.SAML2SSOUserProvisionDataHolder;

import java.util.Map;

/**
 * This class represents user provision service
 */
public class SAML2SSOUserProvisionService {
    private static final Log log = LogFactory.getLog(SAML2SSOUserProvisionService.class);
    private boolean isInit = false;
    private static SAML2SSOUserProvisioner implInstance;

    public SAML2SSOUserProvisionService() {
    }

    public void provisionUser(String username, String response, NativeObject configParameters) {
        try {
            Map<String, String> configs = Utils.convertObject(configParameters);
            initializeConfigParameters(configs);
            implInstance.provisionUser(username, response, configs.get(Constants.PropertyConfig.ISSUER));
        } catch (SAML2SSOUserProvisionException e) {
            log.error("Error occurred while provisioning user " + username, e);
            if (log.isDebugEnabled()) {
                log.debug("SAMLRsponse for user " + username + " : " + response);
            }
        }
    }

    public void initializeConfigParameters(Map<String, String> configParameters) throws SAML2SSOUserProvisionException {
        if (!isInit) {
            if (log.isDebugEnabled()) {
                log.debug("ISSUER = " + configParameters.get(Constants.PropertyConfig.ISSUER));
                for (String key : configParameters.keySet()) {
                    log.info("Key = " + key + "  Value : " + configParameters.get(key));
                }
            }
            SAML2SSOUserProvisionDataHolder.addConfigParameters(configParameters.
                    get(Constants.PropertyConfig.ISSUER), configParameters);
            if (configParameters.containsKey(Constants.PropertyConfig.JIT_PROVISION_SAML2SSO_IMPL_NAME)) {
                Class<?> implClass;
                try {
                    implClass = Class.forName(SAML2SSOUserProvisionDataHolder.
                            getConfigParameters(configParameters.get(Constants.PropertyConfig.ISSUER)).
                            get(Constants.PropertyConfig.JIT_PROVISION_SAML2SSO_IMPL_NAME));
                } catch (ClassNotFoundException e) {
                    throw new SAML2SSOUserProvisionException("Error while loading class " + configParameters.
                            get(Constants.PropertyConfig.JIT_PROVISION_SAML2SSO_IMPL_NAME), e);
                }
                try {
                    if (null != implClass) {
                        implInstance = (SAML2SSOUserProvisioner) implClass.newInstance();
                    }
                } catch (InstantiationException e) {
                    throw new SAML2SSOUserProvisionException("Instantiation Exception while creating instance for " +
                            configParameters.get(Constants.PropertyConfig.JIT_PROVISION_SAML2SSO_IMPL_NAME), e);
                } catch (IllegalAccessException e) {
                    throw new SAML2SSOUserProvisionException("Illegal Access Exception while creating instance for " +
                            configParameters.get(Constants.PropertyConfig.JIT_PROVISION_SAML2SSO_IMPL_NAME), e);
                }
            } else {
                implInstance = new SAML2SSOUserProvisionerImpl();
            }
        }
    }
}
