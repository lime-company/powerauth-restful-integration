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
package io.getlime.security.powerauth.rest.api.spring.provider;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthRequestFilterException;
import io.getlime.security.powerauth.rest.api.spring.model.PowerAuthRequestBody;
import io.getlime.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

/**
 * Abstract class for PowerAuth authentication provider.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public abstract class PowerAuthAuthenticationProviderBase {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthAuthenticationProviderBase.class);

    /**
     * Validate the signature from the PowerAuth HTTP header against the provided HTTP method, request body and URI identifier.
     * Make sure to accept only allowed signatures.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Body of the HTTP request.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedSignatureTypes Allowed types of the signature.
     * @param forcedSignatureVersion Forced signature version during upgrade.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public abstract PowerAuthApiAuthentication validateRequestSignature(String httpMethod, byte[] httpBody, String requestUriIdentifier, String httpAuthorizationHeader, List<PowerAuthSignatureTypes> allowedSignatureTypes, @Nullable Integer forcedSignatureVersion) throws PowerAuthAuthenticationException;

    /**
     * Validate the token digest from PowerAuth authentication header.
     * @param httpAuthorizationHeader HTTP header with token digest.
     * @param allowedSignatureTypes Allowed types of the signature.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public abstract PowerAuthApiAuthentication validateToken(String httpAuthorizationHeader, List<PowerAuthSignatureTypes> allowedSignatureTypes) throws PowerAuthAuthenticationException;

    /**
     * The same as {{@link #validateRequestSignature(String, byte[], String, String, List, Integer)} but uses default accepted signature type (2FA or 3FA) and does not specify forced signature version.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Request body
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthentication validateRequestSignature(String httpMethod, byte[] httpBody, String requestUriIdentifier, String httpAuthorizationHeader) throws PowerAuthAuthenticationException {
        List<PowerAuthSignatureTypes> defaultAllowedSignatureTypes = new ArrayList<>();
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);
        return this.validateRequestSignature(httpMethod, httpBody, requestUriIdentifier, httpAuthorizationHeader, defaultAllowedSignatureTypes, null);
    }

    /**
     * Validate a request signature, make sure only supported signature types are used, do not use forced signature version during upgrade.
     * @param servletRequest HTTPServletRequest with signed data.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedSignatureTypes Allowed types of signatures.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthentication validateRequestSignature(HttpServletRequest servletRequest, String requestUriIdentifier, String httpAuthorizationHeader, List<PowerAuthSignatureTypes> allowedSignatureTypes) throws PowerAuthAuthenticationException {
        // Get HTTP method and body bytes
        String requestMethod = servletRequest.getMethod().toUpperCase();
        byte[] requestBodyBytes = extractRequestBodyBytes(servletRequest);
        return this.validateRequestSignature(requestMethod, requestBodyBytes, requestUriIdentifier, httpAuthorizationHeader, allowedSignatureTypes, null);
    }

    /**
     * Validate a request signature, make sure only supported signature types are used and allow specification of forced signature version.
     * @param servletRequest HTTPServletRequest with signed data.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedSignatureTypes Allowed types of signatures.
     * @param forcedSignatureVersion Forced signature version during upgrade.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthentication validateRequestSignature(HttpServletRequest servletRequest, String requestUriIdentifier, String httpAuthorizationHeader, List<PowerAuthSignatureTypes> allowedSignatureTypes, @Nullable Integer forcedSignatureVersion) throws PowerAuthAuthenticationException {
        // Get HTTP method and body bytes
        String requestMethod = servletRequest.getMethod().toUpperCase();
        byte[] requestBodyBytes = extractRequestBodyBytes(servletRequest);
        return this.validateRequestSignature(requestMethod, requestBodyBytes, requestUriIdentifier, httpAuthorizationHeader, allowedSignatureTypes, forcedSignatureVersion);
    }

    /**
     * The same as {{@link #validateRequestSignature(HttpServletRequest, String, String, List, Integer)} but uses default accepted signature type (2FA or 3FA) and does not specify forced signature version.
     * @param servletRequest HTTPServletRequest with signed data.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthentication validateRequestSignature(HttpServletRequest servletRequest, String requestUriIdentifier, String httpAuthorizationHeader) throws PowerAuthAuthenticationException {
        List<PowerAuthSignatureTypes> defaultAllowedSignatureTypes = new ArrayList<>();
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);
        return this.validateRequestSignature(servletRequest, requestUriIdentifier, httpAuthorizationHeader, defaultAllowedSignatureTypes, null);
    }

    /**
     * Validate the token digest from PowerAuth authentication header.
     * @param tokenHeader HTTP header with token digest.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthentication validateToken(String tokenHeader) throws PowerAuthAuthenticationException {
        List<PowerAuthSignatureTypes> defaultAllowedSignatureTypes = new ArrayList<>();
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);
        return this.validateToken(tokenHeader, defaultAllowedSignatureTypes);
    }

    /**
     * Extract request body bytes from HTTP servlet request. In case the data was transparently decrypted, use the decrypted request data.
     * @param servletRequest HTTP servlet request.
     * @return Request body bytes.
     * @throws PowerAuthAuthenticationException In case request body is invalid.
     */
    public byte[] extractRequestBodyBytes(HttpServletRequest servletRequest) throws PowerAuthAuthenticationException {
        if (servletRequest.getAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT) != null) {
            // Implementation of sign-then-encrypt - in case the encryption object is present and signature is validate, use decrypted request data
            PowerAuthEciesEncryption<?> eciesEncryption = (PowerAuthEciesEncryption<?>) servletRequest.getAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT);
            return eciesEncryption.getDecryptedRequest();
        } else {
            // Request data was not encrypted - use regular PowerAuth request body for signature validation
            PowerAuthRequestBody requestBody = ((PowerAuthRequestBody) servletRequest.getAttribute(PowerAuthRequestObjects.REQUEST_BODY));
            if (requestBody == null) {
                logger.warn("The X-PowerAuth-Request-Body request attribute is missing. Register the PowerAuthRequestFilter to fix this error.");
                throw new PowerAuthRequestFilterException();
            }
            return requestBody.getRequestBytes();
        }
    }
}
