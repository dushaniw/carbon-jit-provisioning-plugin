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

package org.wso2.carbon.user.provision;

import org.wso2.carbon.user.provision.common.SAML2SSOUserProvisionException;

/**
 * Interface that is usd to provision users/roles based on the saml response
 */
public interface SAML2SSOUserProvisioner {

    /**
     * This method is used to provision users/roles based on the SAML response.
     * @param username logged in user
     * @param response decoded saml response
     * @param issuer name of the issuer
     * @return user provision is success or not
     * @throws org.wso2.carbon.user.provision.common.SAML2SSOUserProvisionException
     */
    boolean provisionUser(String username, String response, String issuer) throws SAML2SSOUserProvisionException;
}
