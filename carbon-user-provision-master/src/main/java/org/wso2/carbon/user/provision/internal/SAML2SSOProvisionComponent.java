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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.provision.service.SAML2SSOUserProvisionService;

/**
 * This is a service component class
 * Sole purpose of this class is to act as the component for the osgi bundle.
 *
 * @scr.component name="org.wso2.carbon.apimgt.provision" immediate="true"
 * @scr.reference name="user.realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService" unbind="unsetRegistryService"
 */
public class SAML2SSOProvisionComponent {
    private static final Log log = LogFactory.getLog(SAML2SSOProvisionComponent.class);


    protected void activate(ComponentContext componentContext) {
        try {
            if (log.isDebugEnabled()) {
                log.debug("Initializing SAML2 SSO User Provision bundle");
            }
            /* Registering User Provision service */
            BundleContext bundleContext = componentContext.getBundleContext();
            ServiceRegistration<SAML2SSOUserProvisionService> service = bundleContext.registerService(SAML2SSOUserProvisionService.class,
                    new SAML2SSOUserProvisionService(), null);
        } catch (Throwable e) {
            String msg = "Error occurred while SAML2 SSO User Provision bundle";
            log.error(msg, e);
        }
        if (log.isDebugEnabled()) {
            log.debug("SAML2 SSO User Provision Component activated");
        }
    }

    protected void deactivate(ComponentContext componentContext) {
        if (log.isDebugEnabled()) {
            log.debug("SAML2SSOProvisionerComponent deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        if (realmService != null && log.isDebugEnabled()) {
            log.debug("Realm service initialized");
        }
        SAML2SSOUserProvisionDataHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        SAML2SSOUserProvisionDataHolder.setRealmService(null);
    }

    protected void setRegistryService(RegistryService registryService) {
        if (registryService != null && log.isDebugEnabled()) {
            log.debug("Registry service initialized");
        }
        SAML2SSOUserProvisionDataHolder.setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        SAML2SSOUserProvisionDataHolder.setRegistryService(null);
    }
}
