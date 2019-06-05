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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.util.SecurityManager;
import org.mozilla.javascript.NativeObject;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * This class holds utility methods
 */
public class Utils {
    private static final String SECURITY_MANAGER_PROPERTY = org.apache.xerces.impl.Constants.XERCES_PROPERTY_PREFIX +
            org.apache.xerces.impl.Constants.SECURITY_MANAGER_PROPERTY;
    private static final int ENTITY_EXPANSION_LIMIT = 0;
    private static Log log = LogFactory.getLog(Utils.class);

    /**
     * Constructing the XMLObject Object from a String
     *
     * @param authElement
     * @return Corresponding XMLObject which is a SAML2 object
     * @throws SAML2SSOUserProvisionException
     */
    public static XMLObject unmarshall(Element authElement) throws SAML2SSOUserProvisionException {

        XMLObject response;
        try {
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(authElement);
            response = unmarshaller.unmarshall(authElement);
            // Check for duplicate samlp:Response
            NodeList list = response.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20P_NS, "Response");
            if (list.getLength() > 0) {
                log.error("Invalid schema for the SAML2 response. Multiple responses detected");
                throw new SAML2SSOUserProvisionException("Error occurred while processing saml2 response due to " +
                        "Invalid schema for the SAML2 response. Multiple responses detected");
            }

            NodeList assertionList = response.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20_NS,
                    "Assertion");
            if (response instanceof Assertion) {
                if (assertionList.getLength() > 0) {
                    log.error("Invalid schema for the SAML2 assertion(assertionList.getLength() > 0). " +
                            "Multiple assertions detected");
                    throw new SAML2SSOUserProvisionException("Error occurred while processing saml2 response");
                }
            } else {
                if (assertionList.getLength() > 1) {
                    log.error("Invalid schema for the SAML2 response(assertionList.getLength() > 1). " +
                            "Multiple assertions detected");
                    throw new SAML2SSOUserProvisionException("Error occurred while processing saml2 response");
                }
            }
            return response;
        } catch (UnmarshallingException e) {
            throw new SAML2SSOUserProvisionException("UnmarshallingException occurred while processing saml2 " +
                    "response", e);
        }

    }

    /**
     * Get the SAML response document element from response
     *
     * @param authReqStr : decoded saml response
     * @return saml response as a Element
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException
     */
    public static Element getDocumentElement(String authReqStr) throws ParserConfigurationException, IOException,
            SAXException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);

        documentBuilderFactory.setExpandEntityReferences(false);
        documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        org.apache.xerces.util.SecurityManager securityManager = new SecurityManager();
        securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
        documentBuilderFactory.setAttribute(SECURITY_MANAGER_PROPERTY, securityManager);

        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = docBuilder.parse(new ByteArrayInputStream(authReqStr.trim()
                .getBytes()));
        return document.getDocumentElement();
    }

    /**
     * Derive a Map from nativeObject config parameters
     *
     * @param jsObject configuration parameters NativeObject
     * @return configuration parameters
     */
    public static Map<String, String> convertObject(NativeObject jsObject) {
        Object[] ids = jsObject.getIds();
        Map<String, String> mapParams = new HashMap<String, String>(ids.length);
        for (Map.Entry<Object, Object> e : jsObject.entrySet()) {
            log.info("entry : " + e.getKey() + " " + e.getValue());
            if (null != e && !e.toString().isEmpty()) {
                mapParams.put(e.getKey().toString(), e.getValue().toString());
            }
        }
        return mapParams;
    }
}
