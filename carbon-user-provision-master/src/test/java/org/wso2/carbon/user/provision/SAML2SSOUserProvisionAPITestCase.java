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

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.impl.StaticLoggerBinder;
import org.w3c.dom.Element;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
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
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

//import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Configuration.class, MultitenantUtils.class, StaticLoggerBinder.class})

/**
 * SAML2 SSo User Provision API Test class
 */
public class SAML2SSOUserProvisionAPITestCase {

    private static SAML2SSOUserProvisioner SAML2SSOUserProvisionerAPI;
    private static UserRealm realm;
    private static String username;
    private static String issuer;
    private static String decodedSAMLResponse;
    private static Map<String, String> configParameters;

    @BeforeClass
    public static void setUp() {

        username = "pubuser1";
        issuer = "API_PUBLISHER";
        decodedSAMLResponse = "<?xml version=\"1.0\"?>\n" +
                "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Version=\"2.0\" ID=\"oLxIYnearVgA_DK88a3Cqi8sGJy\" IssueInstant=\"2018-06-29T09:13:15.965Z\" InResponseTo=\"nhfgbehpgiifglcdncdecmjcioodpmidicobhdde\">\n" +
                "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">IDLabRepsol</saml:Issuer>\n" +
                "<samlp:Status>\n" +
                "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n" +
                "</samlp:Status>\n" +
                "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"lRstTeFBJtp2I2eqeW_Kcg732YO\" IssueInstant=\"2018-06-29T09:13:16.386Z\" Version=\"2.0\">\n" +
                "<saml:Issuer>IDLabRepsol</saml:Issuer>\n" +
                "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "<ds:SignedInfo>\n" +
                "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n" +
                "<ds:Reference URI=\"#lRstTeFBJtp2I2eqeW_Kcg732YO\">\n" +
                "<ds:Transforms>\n" +
                "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
                "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "</ds:Transforms>\n" +
                "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
                "<ds:DigestValue>eqU4mTM9RkBl8zKR3ru+QfbD0HVrE1lk01nN8IOHWJo=</ds:DigestValue>\n" +
                "</ds:Reference>\n" +
                "</ds:SignedInfo>\n" +
                "<ds:SignatureValue>dWbJFd87U3YzMEmYjSL0uVt090vQU17E8p+fRI5nBvJS0QQgV0zHn+XyqHTAImf2M4lrA/WXx30VAsPsaqR2/YrCFSLcaK96PQneOW0MwKh1aPyHlmtZnfOUAhkFTKwWXUQwKxr5jyU4KEIB3RMUjCCdi6cqmfIg3MFr/s/wy9n/K9VETqQfaNiMLwPk2/jSaCL5TPCx8m5Csojua8EgFkh41nelpXkuxxnkbKQTjKvLB5UlrDB+21NT8cFa66SBASGRyTxuSL2Z9tTbz8sv2azePwBCkeGHGWNWyqdVsv3SkMaxjpo5vB7ikbUHnSWayL/7Y/It9Ff79ikYoVbLrA==</ds:SignatureValue>\n" +
                "<ds:KeyInfo>\n" +
                "<ds:X509Data>\n" +
                "<ds:X509Certificate>MIIC+DCCAeCgAwIBAgIGAVzJz78KMA0GCSqGSIb3DQEBCwUAMD0xCzAJBgNVBAYTAlNQMQ8wDQYDVQQKEwZSZXBzb2wxHTAbBgNVBAMTFFJlcHNvbFByZXByb2R1Y2Npb24yMB4XDTE3MDYyMTA4NDA1NFoXDTIyMDUyNjA4NDA1NFowPTELMAkGA1UEBhMCU1AxDzANBgNVBAoTBlJlcHNvbDEdMBsGA1UEAxMUUmVwc29sUHJlcHJvZHVjY2lvbjIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDM72/jG42NneHVnQvbiiwv/GJCSBHfYGf6csf8IUYw0yLhn0SFMxTq1Xaf/ZU10U44xBLK2ca0YPt7HnQH91MWCEClctd7orHvBkMpLXm87oysJhg48Y84spIMlm8T9H9zIQnPy4wIsc8/nC0xD7frfTRDqFcooM9JM9BS8pdmyYKqULdnHefie5xgvCTJIQmcrKqs+uLh8XvH6ToYNCfGkw+c4OoRkdXEk7z+wtiCvTK8fOslrQoyweht2py5Snu8fBJdSnUS6QpsRnLAiPjk9IsxhCC35NbYWawlOQTDb3PNLAWmPtFoT8C43NNqA9eXe5KGOjmKrR3J0zqNFzpfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAI2h/OkJfSP8yqYMljK1lMoRHFoSMvvamUSH/81C5efk8rkSCoP3scR7p3xAo8cjr7xI3cqoMbJjqGWuBx/9JnHpsLznAp+cBjyhcpmlSlixNNBNZZAu9AYZdlYlK+JAW/SCFuUchOaFpu9+9Y07crlHSGRGjxd0j2GOF3ANpqp4lPK707MHMfWT3I/j7T/SUlXs6UwVRES14y+j0XsjaHEOodO7GT8ZCa7PYFt1i8VeesbrsyMgbs8sIOcYA7R2lkIxa2h2cBdRySZTU6nKPghzBSvse3f+j1aHbbq8UpqSiOCGi52qsNRYxp795vv+c2vkRtdI7zzcF8cYAW1P4B4=</ds:X509Certificate>\n" +
                "</ds:X509Data>\n" +
                "<ds:KeyValue>\n" +
                "<ds:RSAKeyValue>\n" +
                "<ds:Modulus>zO9v4xuNjZ3h1Z0L24osL/xiQkgR32Bn+nLH/CFGMNMi4Z9EhTMU6tV2n/2VNdFOOMQSytnGtGD7ex50B/dTFghApXLXe6Kx7wZDKS15vO6MrCYYOPGPOLKSDJZvE/R/cyEJz8uMCLHPP5wtMQ+36300Q6hXKKDPSTPQUvKXZsmCqlC3Zx3n4nucYLwkySEJnKyqrPri4fF7x+k6GDQnxpMPnODqEZHVxJO8/sLYgr0yvHzrJa0KMsHobdqcuUp7vHwSXUp1EukKbEZywIj45PSLMYQgt+TW2FmsJTkEw29zzSwFpj7RaE/AuNzTagPXl3uShjo5iq0dydM6jRc6Xw==</ds:Modulus>\n" +
                "<ds:Exponent>AQAB</ds:Exponent>\n" +
                "</ds:RSAKeyValue>\n" +
                "</ds:KeyValue>\n" +
                "</ds:KeyInfo>\n" +
                "</ds:Signature>\n" +
                "<saml:Subject>\n" +
                "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">pubuser1</saml:NameID>\n" +
                "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
                "<saml:SubjectConfirmationData Recipient=\"https://51.140.250.5:9443/publisher/jagg/jaggery_acs.jag\" NotOnOrAfter=\"2018-06-29T09:18:16.386Z\" InResponseTo=\"nhfgbehpgiifglcdncdecmjcioodpmidicobhdde\"/>\n" +
                "</saml:SubjectConfirmation>\n" +
                "</saml:Subject>\n" +
                "<saml:Conditions NotBefore=\"2018-06-29T09:08:16.386Z\" NotOnOrAfter=\"2018-06-29T09:18:16.386Z\">\n" +
                "<saml:AudienceRestriction>\n" +
                "<saml:Audience>API_PUBLISHER</saml:Audience>\n" +
                "</saml:AudienceRestriction>\n" +
                "<saml:AudienceRestriction>\n" +
                "<saml:Audience>https://51.140.250.5:9443/oauth2/token</saml:Audience>\n" +
                "</saml:AudienceRestriction>\n" +
                "</saml:Conditions>\n" +
                "<saml:AuthnStatement SessionIndex=\"lRstTeFBJtp2I2eqeW_Kcg732YO\" AuthnInstant=\"2018-06-29T09:13:16.324Z\">\n" +
                "<saml:AuthnContext>\n" +
                "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>\n" +
                "</saml:AuthnContext>\n" +
                "</saml:AuthnStatement>\n" +
                "<saml:AttributeStatement>\n" +
                "<saml:Attribute Name=\"http://wso2.org/claims/userid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified\">\n" +
                "<saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">pubuser1</saml:AttributeValue>\n" +
                "</saml:Attribute>\n" +
                "<saml:Attribute Name=\"role\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified\">\n" +
                "<saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">apipublisher</saml:AttributeValue>\n" +
                "<saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">apisubscriber</saml:AttributeValue>\n" +
                "</saml:Attribute>\n" +
                "<saml:Attribute Name=\"userid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified\">\n" +
                "<saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">pubuser1</saml:AttributeValue>\n" +
                "</saml:Attribute>\n" +
                "</saml:AttributeStatement>\n" +
                "</saml:Assertion>\n" +
                "</samlp:Response>";
        configParameters = new HashMap<String, String>();
        configParameters.put(Constants.JITPSAML2SSO_AUTHENTICATOR_NAME, "org.wso2.carbon.user.provision.service.SAML2SSOUserProvisionerImpl");
        configParameters.put(Constants.ROLE_ATTRIBUTE_NAME, "role");
        configParameters.put(Constants.PropertyConfig.JIT_USER_PROVISIONING_ENABLED, "true");
        configParameters.put(Constants.PropertyConfig.PROVISIONING_DEFAULT_ROLE, "Internal/everyone");
        configParameters.put(Constants.PropertyConfig.ROLE_CLAIM_ATTRIBUTE, Constants.ROLE_ATTRIBUTE_NAME);
        configParameters.put(Constants.PropertyConfig.IS_SUPER_ADMIN_ROLE_REQUIRED, "true");
        configParameters.put(Constants.PropertyConfig.PROVISIONING_DEFAULT_USERSTORE, "PRIMARY");

        SAML2SSOUserProvisionDataHolder.addConfigParameters(issuer, configParameters);
    }

    @Test
    public void testAddNewUser() throws UserStoreException, SAML2SSOUserProvisionException, SAXException, IOException,
            ParserConfigurationException, UnmarshallingException {
        boolean expectedResult = true;

        SAML2SSOUserProvisionerImpl impl = new SAML2SSOUserProvisionerImpl();
        realm = mock(UserRealm.class);
        RealmConfiguration realmConfiguration = mock(RealmConfiguration.class);
        PowerMockito.mockStatic(MultitenantUtils.class);
        UserStoreManager userStoreManager = mock(UserStoreManager.class);

        Unmarshaller unmarshaller = mock(Unmarshaller.class);
        UnmarshallerFactory unmarshallerFactory = mock(UnmarshallerFactory.class);
        Element authElement = Utils.getDocumentElement(decodedSAMLResponse);
        XMLObject response = mock(XMLObject.class);

        PowerMockito.mockStatic(Configuration.class);
//        when(Configuration.getUnmarshallerFactory()).thenReturn(unmarshallerFactory);
        when(unmarshallerFactory.getUnmarshaller(authElement)).thenReturn(unmarshaller);

        when(realm.getUserStoreManager()).thenReturn(userStoreManager);
        when(realm.getUserStoreManager().getSecondaryUserStoreManager("PRIMARY")).thenReturn(userStoreManager);
        when(realm.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(userStoreManager.isExistingUser("pubuser1")).thenReturn(false);
        when(userStoreManager.getRoleNames()).thenReturn(new String[]{"apipublisher","apisubscriber","apicreator",
                "Internal/everyone"});
        when(userStoreManager.getRoleListOfUser("pubuser1")).thenReturn(new String[]{});
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(MultitenantUtils.getTenantAwareUsername("pubuser1")).thenReturn("pubuser1");
        when(realmConfiguration.getEveryOneRoleName()).thenReturn("Internal/everyone");
        when(realmConfiguration.isPrimary()).thenReturn(true);
        when(realmConfiguration.getAdminUserName()).thenReturn("admin");
        when(unmarshaller.unmarshall(authElement)).thenReturn(response);

        String[] newRoles = new String[]{"apipublisher","apisubscriber"};
        assertEquals(expectedResult, impl.provisionUser(username, realm, newRoles, issuer));
    }

    @Test
    public void testUpdateExistingUser() throws UserStoreException, SAML2SSOUserProvisionException {
        boolean expectedResult = true;

        SAML2SSOUserProvisionerImpl impl = new SAML2SSOUserProvisionerImpl();
        XMLObject xmlObject = null;
        SAML2SSOUserProvisionerAPI = mock(SAML2SSOUserProvisioner.class);
        UserStoreManager userStoreManager = mock(UserStoreManager.class);
        realm = mock(UserRealm.class);
        RealmConfiguration realmConfiguration = mock(RealmConfiguration.class);
        mockStatic(MultitenantUtils.class);
        when(realm.getUserStoreManager()).thenReturn(userStoreManager);
        when(realm.getUserStoreManager().getSecondaryUserStoreManager("PRIMARY")).thenReturn(userStoreManager);
        when(realm.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(userStoreManager.isExistingUser("pubuser1")).thenReturn(true);
        when(userStoreManager.getRoleNames()).thenReturn(new String[]{""});
        when(userStoreManager.getRoleListOfUser("pubuser1")).thenReturn(new String[]{""});
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(MultitenantUtils.getTenantAwareUsername("pubuser1")).thenReturn("pubuser1");
        when(realmConfiguration.getEveryOneRoleName()).thenReturn("Internal/everyone");
        when(realmConfiguration.isPrimary()).thenReturn(true);
        when(realmConfiguration.getAdminUserName()).thenReturn("admin");
        String[] newRoles = new String[]{"apipublisher","apisubscriber"};

        assertEquals(expectedResult, impl.provisionUser(username, realm, newRoles, issuer));
    }
}
