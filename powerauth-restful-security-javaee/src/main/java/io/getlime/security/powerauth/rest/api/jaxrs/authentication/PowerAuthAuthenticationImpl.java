/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.rest.api.jaxrs.authentication;

/**
 * PowerAuth authentication object used between PowerAuth Client and intermediate server
 * application (such as mobile banking API).
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthAuthenticationImpl {

    private String activationId;
    private String applicationKey;
    private String signature;
    private String signatureType;
    private String requestUri;
    private String httpMethod;
    private byte[] nonce;
    private byte[] data;

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

}
