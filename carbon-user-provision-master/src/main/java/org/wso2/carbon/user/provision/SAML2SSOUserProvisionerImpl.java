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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.provision.common.Constants;
import org.wso2.carbon.user.provision.common.SAML2SSOUserProvisionException;
import org.wso2.carbon.user.provision.common.Utils;
import org.wso2.carbon.user.provision.internal.SAML2SSOUserProvisionDataHolder;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

import static org.wso2.carbon.user.provision.common.Constants.InternalRoleDomains.APPLICATION_DOMAIN;
import static org.wso2.carbon.user.provision.common.Constants.InternalRoleDomains.WORKFLOW_DOMAIN;

/**
 * Ths class provides the implementation for the services exposed by the service class.
 * Which provisions users who are login to jaggery applications. This is only supported in super tenant mode as of v1.0.0.
 */
public class SAML2SSOUserProvisionerImpl implements SAML2SSOUserProvisioner {
    private static final Log log = LogFactory.getLog(SAML2SSOUserProvisionerImpl.class);
    private static final Log AUDIT_LOG = LogFactory.getLog("AUDIT_LOG");
    private static final String AUTHENTICATOR_NAME = Constants.JITPSAML2SSO_AUTHENTICATOR_NAME;
    private SecureRandom random = new SecureRandom();
    private String auditResult = Constants.AUDIT_RESULT_FAILED;

    private static void handleException(Exception e) {
        String errorMessage = "Error while Authorizing User : " + e.getMessage();
        log.error(errorMessage, e);
    }

    public SAML2SSOUserProvisionerImpl() {
    }

    public boolean provisionUser(String username, String response, String issuer) throws SAML2SSOUserProvisionException {
        XMLObject xmlObject;
        boolean isUserProvisionSuccessful = false;
        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        Element authElement = null;
        try {
            authElement = Utils.getDocumentElement(response);
        } catch (ParserConfigurationException e) {
            handleException(e);
        } catch (IOException e) {
            handleException(e);
        } catch (SAXException e) {
            handleException(e);
        }
        xmlObject = Utils.unmarshall(authElement);
        try {
            UserRealm realm = AnonymousSessionUtil.
                    getRealmByTenantDomain(SAML2SSOUserProvisionDataHolder.getRegistryService(),
                            SAML2SSOUserProvisionDataHolder.getRealmService(), tenantDomain);
            String[] newRoles = getRoles(xmlObject, issuer);
            // Starting user provisioning
            isUserProvisionSuccessful = provisionUser(username, realm, newRoles, issuer);

        } catch (CarbonException e) {
            handleException(e);
        } catch (UserStoreException e) {
            handleException(e);
        }
        if (username != null && username.trim().length() > 0 && AUDIT_LOG.isInfoEnabled()) {

            String auditInitiator = username + UserCoreConstants.TENANT_DOMAIN_COMBINER + tenantDomain;
            String auditData = "";

            AUDIT_LOG.info(String.format(Constants.AUDIT_MESSAGE,
                    auditInitiator, Constants.AUDIT_ACTION_PROVISION, AUTHENTICATOR_NAME,
                    auditData, auditResult));
        }
        return isUserProvisionSuccessful;
    }

    /**
     * Provision/Create user on the server(SP) and update roles accordingly
     *
     * @param username logged in fully qualified username
     * @param realm    realm configuration
     * @param newRoles roles coming from the saml assertion
     * @param issuer issuer name
     * @throws UserStoreException
     * @throws SAML2SSOUserProvisionException
     * @return provision is success or not
     */
    protected boolean provisionUser(String username, UserRealm realm, String[] newRoles, String issuer) throws UserStoreException,
            SAML2SSOUserProvisionException {
        boolean isUserProvisionSuccess = false;
        boolean isJITProvisioningEnabled = false;
        Map<String, String> configParameters = SAML2SSOUserProvisionDataHolder.getConfigParameters(issuer);
        if (configParameters.containsKey(Constants.PropertyConfig.JIT_USER_PROVISIONING_ENABLED)) {
            isJITProvisioningEnabled = Boolean.parseBoolean(configParameters.get(Constants.PropertyConfig.
                    JIT_USER_PROVISIONING_ENABLED));
        }

        if (isJITProvisioningEnabled) {
            String userStoreDomain = null;
            if (configParameters.containsKey(Constants.PropertyConfig.PROVISIONING_DEFAULT_USERSTORE)) {
                userStoreDomain = configParameters.get(Constants.PropertyConfig.PROVISIONING_DEFAULT_USERSTORE);
            }

            UserStoreManager userStore = null;


            if (null != userStoreDomain && !userStoreDomain.isEmpty()) {
                userStore = realm.getUserStoreManager().getSecondaryUserStoreManager(userStoreDomain);
            }

            // If default user store is invalid or not specified use primary user store
            if (null == userStore) {
                try {
                    userStore = realm.getUserStoreManager();
                } catch (UserStoreException e) {
                    log.error("Error while obtaining user store for user: " + username, e);
                    throw new SAML2SSOUserProvisionException("Error while obtaining user store for user: " + username, e);
                }
            }
            // Load default role if assersion do not specify roles
            if (null == newRoles || newRoles.length == 0) {
                if (configParameters.containsKey(Constants.PropertyConfig.PROVISIONING_DEFAULT_ROLE)) {
                    newRoles = new String[]{configParameters.get(Constants.PropertyConfig.PROVISIONING_DEFAULT_ROLE)};
                } else {
                    newRoles = new String[]{};
                }
            }


            if (log.isDebugEnabled()) {
                log.debug("User " + username + " contains roles : " + Arrays.toString(newRoles) +
                        " as per response and (default role) config");
            }
            if (null != userStore) {
                // addingRoles = newRoles AND allExistingRoles
                Collection<String> rolesToBeAdded = new ArrayList<String>();
                Collections.addAll(rolesToBeAdded, newRoles);

                Collection<String> allExistingRoles = Arrays.asList(userStore.getRoleNames());

                //validate rolesToBeAdded against all the available roles in the userstore
                rolesToBeAdded.retainAll(allExistingRoles);
                username = MultitenantUtils.getTenantAwareUsername(username);
                if (userStore.isExistingUser(username)) {
                    // Update an already existing user
                    List<String> currentRolesList = Arrays.asList(userStore.getRoleListOfUser(username));
                    // addingRoles = (newRoles AND existingRoles) - currentRolesList)
                    rolesToBeAdded.removeAll(currentRolesList);

                    Collection<String> rolesToBeDeleted = retrieveRolesToBeDeleted(realm, currentRolesList, Arrays.asList(newRoles));

                    RealmConfiguration realmConfiguration = realm.getRealmConfiguration();

                    // Check for case whether super admin login
                    if (userStore.getRealmConfiguration().isPrimary() && username.equals(realmConfiguration.getAdminUserName())) {
                        boolean isSuperAdminRoleRequired = false;
                        if (configParameters.containsKey(Constants.PropertyConfig.IS_SUPER_ADMIN_ROLE_REQUIRED)) {
                            isSuperAdminRoleRequired = Boolean.parseBoolean(configParameters.get(Constants.PropertyConfig.
                                    IS_SUPER_ADMIN_ROLE_REQUIRED));
                        }

                        // Whether superadmin login without superadmin role is permitted from the saml response
                        if (!isSuperAdminRoleRequired && rolesToBeDeleted.contains(realmConfiguration.getAdminRoleName())) {
                            // Avoid removing superadmin role from superadmin user.
                            rolesToBeDeleted.remove(realmConfiguration.getAdminRoleName());
                            log.warn("Proceeding with allowing super admin to be logged in, even though response doesn't" +
                                    " include super admin role assigned for the superadmin user.");
                        }
                    }

                    if (log.isDebugEnabled()) {
                        log.debug("Deleting roles : " + Arrays.toString(rolesToBeDeleted.toArray(new String[rolesToBeDeleted.size()])) +
                                " and Adding roles : " + Arrays.toString(rolesToBeAdded.toArray(new String[rolesToBeAdded.size()])));
                    }
                    userStore.updateRoleListOfUser(username, rolesToBeDeleted.toArray(new String[rolesToBeDeleted.size()]),
                            rolesToBeAdded.toArray(new String[rolesToBeAdded.size()]));
                    if (log.isDebugEnabled()) {
                        log.debug("User: " + username + " is updated via SAML authenticator with roles : " +
                                Arrays.toString(newRoles));
                    }
                } else {
                    userStore.addUser(username, generatePassword(), rolesToBeAdded.
                            toArray(new String[rolesToBeAdded.size()]), null, null);
                    if (log.isDebugEnabled()) {
                        log.debug("User: " + username + " is provisioned via SAML2 User Provision Service with roles : "
                                + Arrays.toString(rolesToBeAdded.toArray(new String[rolesToBeAdded.size()])));
                    }
                }
                isUserProvisionSuccess = true;
            } else {
                throw new SAML2SSOUserProvisionException("Unable to find the user store manager for User: " + username);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("User provisioning disabled");
            }
        }
        auditResult = Constants.AUDIT_RESULT_SUCCESS;
        return isUserProvisionSuccess;
    }

    /**
     * Get roles from the SAML2 XMLObject
     *
     * @param xmlObject SAML2 XMLObject
     * @param issuer issuer name
     * @return String array of roles
     */
    private String[] getRoles(XMLObject xmlObject, String issuer) {
        if (xmlObject instanceof Response) {
            return getRolesFromResponse((Response) xmlObject, issuer);
        } else if (xmlObject instanceof Assertion) {
            return getRolesFromAssertion((Assertion) xmlObject, issuer);
        } else {
            return new String[]{};
        }
    }

    /**
     * Generates (random) password for user to be provisioned
     *
     * @return generated password
     */
    private String generatePassword() {
        return new BigInteger(130, random).toString(32);
    }

    /**
     * Get roles from the SAML2 Response
     *
     * @param response SAML2 Response
     * @param issuer issuer name
     * @return roles array
     */
    private String[] getRolesFromResponse(Response response, String issuer) {
        List<Assertion> assertions = response.getAssertions();
        Assertion assertion = null;
        if (assertions != null && assertions.size() > 0) {
            assertion = assertions.get(0);
            return getRolesFromAssertion(assertion, issuer);
        }
        return null;
    }

    /**
     * Get the username from the SAML2 Assertion
     *
     * @param assertion SAML2 assertion
     * @param issuer issuer name
     * @return username
     */
    private String[] getRolesFromAssertion(Assertion assertion, String issuer) {
        List<String> roles = new ArrayList<String>();
        String roleClaim = getRoleClaim(issuer);
        List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();

        if (attributeStatementList != null) {
            for (AttributeStatement statement : attributeStatementList) {
                List<Attribute> attributesList = statement.getAttributes();
                for (Attribute attribute : attributesList) {
                    String attributeName = attribute.getName();
                    if (attributeName != null && roleClaim.equals(attributeName)) {
                        // Assumes role claim appear only once
                        List<XMLObject> attributeValueList = attribute.getAttributeValues();
                        for (XMLObject attributeValue : attributeValueList){
                            String attrVal = attributeValue.getDOM().getTextContent();
                            roles.add(attrVal);
                            if (log.isDebugEnabled()) {
                                log.debug("AttributeName : " + attributeName + ", AttributeValue : " + attrVal);
                            }
                        }
                        if (log.isDebugEnabled()) {
                            log.debug("Role list : " + roles);
                        }
                    }
                }
            }
        }
        return roles.toArray(new String[0]);
    }

    /**
     * Role claim attribute value from configuration file or from constants
     * @param issuer issuer name
     * @return role claim attribute name
     */
    private String getRoleClaim(String issuer) {
        if (SAML2SSOUserProvisionDataHolder.getConfigParameters(issuer).containsKey(Constants.PropertyConfig.ROLE_CLAIM_ATTRIBUTE)) {
            return SAML2SSOUserProvisionDataHolder.getConfigParameters(issuer).get(Constants.PropertyConfig.ROLE_CLAIM_ATTRIBUTE);
        } else {
            return Constants.ROLE_ATTRIBUTE_NAME;
        }
    }

    /**
     * Retrieve the list of roles to be deleted.
     *
     * @param realm            user realm
     * @param currentRolesList current role list of the user
     * @param rolesToAdd       roles that are about to be added
     * @return roles to be deleted
     * @throws UserStoreException
     */
    protected List<String> retrieveRolesToBeDeleted(UserRealm realm, List<String> currentRolesList,
                                                    List<String> rolesToAdd) throws UserStoreException {

        List<String> deletingRoles = new ArrayList<String>();
        deletingRoles.addAll(currentRolesList);

        // deletingRoles = currentRolesList - rolesToAdd
        deletingRoles.removeAll(rolesToAdd);

        // Exclude Internal/everyonerole from deleting role since its cannot be deleted
        deletingRoles.remove(realm.getRealmConfiguration().getEveryOneRoleName());

        // Remove all internal roles from deleting list
        deletingRoles.removeAll(extractInternalRoles(currentRolesList));

        return deletingRoles;
    }

    /**
     * Extract all internal roles from a list of provided roles.
     *
     * @param allRoles list of roles to filter from
     * @return internal role list
     */
    private List<String> extractInternalRoles(List<String> allRoles) {

        List<String> internalRoles = new ArrayList();

        for (String role : allRoles) {
            if (StringUtils.contains(role, APPLICATION_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR)
                    || StringUtils.contains(role, WORKFLOW_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR)) {
                internalRoles.add(role);
            }
        }

        return internalRoles;
    }

}
