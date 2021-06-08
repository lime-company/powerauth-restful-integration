/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.getlime.security.powerauth.rest.api.spring.authentication.impl;

import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthSignatureAuthentication;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * PowerAuth authentication object used between PowerAuth Client and intermediate server
 * application (such as mobile banking API).
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthSignatureAuthenticationImpl extends AbstractAuthenticationToken implements PowerAuthSignatureAuthentication {

    private static final long serialVersionUID = 6495166873663643144L;

    /**
     * Activation ID.
     */
    private String activationId;

    /**
     * Application key.
     */
    private String applicationKey;

    /**
     * Signature value.
     */
    private String signature;

    /**
     * Signature type.
     */
    private String signatureType;

    /**
     * Request URI identifier.
     */
    private String requestUri;

    /**
     * Used HTTP method.
     */
    private String httpMethod;

    /**
     * Cryptographic nonce.
     */
    private byte[] nonce;

    /**
     * Signed data.
     */
    private byte[] data;

    /**
     * Signature version.
     */
    private String version;

    /**
     * Forced signature version. Used during scheme upgrade, when the element already uses new signature type but
     * some parts of the process still need to work with the old one.
     */
    private Integer forcedSignatureVersion;

    /**
     * Reference to the original HTTP header.
     */
    private PowerAuthHttpHeader httpHeader;

    /**
     * Default constructor.
     */
    public PowerAuthSignatureAuthenticationImpl() {
        super(null);
    }

    // Authentication Token Related methods

    @Override
    public Object getCredentials() {
        return signature;
    }

    @Override
    public Object getPrincipal() {
        return activationId;
    }

    // Getters and setters for fields

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get application key.
     * @return Application key.
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Set application key.
     * @param applicationKey Application key.
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Get signature.
     * @return Signature.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Set signature.
     * @param signature Signature.
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * Get signature type.
     * @return Signature type.
     */
    public String getSignatureType() {
        return signatureType;
    }

    /**
     * Set signature type.
     * @param signatureType Signature type.
     */
    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    /**
     * Get request URI identifier.
     * @return Request URI identifier.
     */
    public String getRequestUri() {
        return requestUri;
    }

    /**
     * Set request URI identifier.
     * @param requestUri Request URI identifier.
     */
    public void setRequestUri(String requestUri) {
        this.requestUri = requestUri;
    }

    /**
     * Get HTTP method.
     * @return HTTP method.
     */
    public String getHttpMethod() {
        return httpMethod;
    }

    /**
     * Set HTTP method.
     * @param httpMethod HTTP method.
     */
    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    /**
     * Get nonce.
     * @return Nonce.
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Set nonce.
     * @param nonce Nonce.
     */
    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    /**
     * Get request data.
     * @return Request data.
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Set request data.
     * @param data Request data.
     */
    public void setData(byte[] data) {
        this.data = data;
    }

    /**
     * Get PowerAuth protocol version.
     * @return PowerAuth protocol version.
     */
    @Override
    public String getVersion() {
        return version;
    }

    /**
     * Set PowerAuth protocol version.
     * @param version PowerAuth protocol version.
     */
    @Override
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Get forced signature version which is used during upgrade.
     * @return Forced signature version.
     */
    @Override
    public Integer getForcedSignatureVersion() {
        return forcedSignatureVersion;
    }

    /**
     * Set forced signature version which is used during upgrade.
     * @param forcedSignatureVersion Forced signature version.
     */
    @Override
    public void setForcedSignatureVersion(Integer forcedSignatureVersion) {
        this.forcedSignatureVersion = forcedSignatureVersion;
    }

    /**
     * Get parsed PowerAuth HTTP header.
     * @return PowerAuth HTTP header.
     */
    @Override
    public PowerAuthHttpHeader getHttpHeader() {
        return httpHeader;
    }

    /**
     * Set parsed PowerAuth HTTP header.
     * @param httpHeader PowerAuth HTTP header.
     */
    @Override
    public void setHttpHeader(PowerAuthHttpHeader httpHeader) {
        this.httpHeader = httpHeader;
    }
}
