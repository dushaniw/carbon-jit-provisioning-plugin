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

package org.wso2.carbon.user.provision.internal;

import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;
import java.util.Map;

/*
* This class holds data related to user provision
* */
public class SAML2SSOUserProvisionDataHolder {

    private static RegistryService registryService;
    private static RealmService realmService;
    private static Map<String, Map<String, String>> configParameters = new Hashtable<String, Map<String, String>>();

    public SAML2SSOUserProvisionDataHolder () {

    }

    public static RegistryService getRegistryService() {
        return registryService;
    }

    public static void setRegistryService(RegistryService registryService) {
        SAML2SSOUserProvisionDataHolder.registryService = registryService;
    }

    public static RealmService getRealmService() {
        return realmService;
    }

    public static void setRealmService(RealmService realmService) {
        SAML2SSOUserProvisionDataHolder.realmService = realmService;
    }

    public static Map<String, String> getConfigParameters(String issuer) {
        return configParameters.get(issuer);
    }

    public static void addConfigParameters(String issuer, Map<String, String> configParameters) {
        if(!SAML2SSOUserProvisionDataHolder.configParameters.containsKey(issuer)){
            SAML2SSOUserProvisionDataHolder.configParameters.put(issuer, new Hashtable<String, String>());
            SAML2SSOUserProvisionDataHolder.configParameters.get(issuer).putAll(configParameters);
        }
    }
}
