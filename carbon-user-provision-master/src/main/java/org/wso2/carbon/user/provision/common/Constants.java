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

package org.wso2.carbon.user.provision.common;

public class Constants {
    public static final java.lang.String AUDIT_MESSAGE = "Initiator : %s | Action : %s | Target : %s | Data : { %s } " +
            "| Result : %s ";
    public static final java.lang.String AUDIT_ACTION_PROVISION = "Provision";
    public static final java.lang.String AUDIT_RESULT_FAILED = "Failed";
    public static final java.lang.String AUDIT_RESULT_SUCCESS = "Success";
    public static final String ROLE_ATTRIBUTE_NAME = "http://wso2.org/claims/role";
    public static final String JITPSAML2SSO_AUTHENTICATOR_NAME = "org.wso2.carbon.user.provision.SAML2SSOUserProvisionerImpl";

    public static class PropertyConfig {
        public static final String ROLE_CLAIM_ATTRIBUTE = "roleClaimAttribute";
        public static final String JIT_USER_PROVISIONING_ENABLED = "JITUserProvisioningEnabled";
        public static final String PROVISIONING_DEFAULT_USERSTORE = "provisioningDefaultUserStore";
        public static final String PROVISIONING_DEFAULT_ROLE = "provisioningDefaultRole";
        public static final String IS_SUPER_ADMIN_ROLE_REQUIRED = "isSuperAdminRoleRequired";
        public static final String JIT_PROVISION_SAML2SSO_IMPL_NAME = "SAML2SSOUserProvisionerImpl";
        public static final String ISSUER = "Issuer";
    }
}
