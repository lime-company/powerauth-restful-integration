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
package io.getlime.security.powerauth.rest.api.jaxrs.provider;

import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.v3.PowerAuthPortV3ServiceStub;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.http.validator.PowerAuthTokenHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthAuthentication;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthSignatureAuthentication;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthTokenAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.authentication.*;
import io.getlime.security.powerauth.rest.api.base.provider.PowerAuthAuthenticationProviderBase;
import io.getlime.security.powerauth.rest.api.jaxrs.authentication.PowerAuthApiAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.jaxrs.authentication.PowerAuthSignatureAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.jaxrs.authentication.PowerAuthTokenAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.jaxrs.converter.v3.SignatureTypeConverter;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ejb.Stateless;
import javax.inject.Inject;
import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.List;

/**
 * Implementation of PowerAuth authentication provider.
 *
 * @author Petr Dvorak
 *
 */
@Stateless
public class PowerAuthAuthenticationProvider extends PowerAuthAuthenticationProviderBase {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthAuthenticationProvider.class);

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    public PowerAuthAuthenticationProvider() {
    }

    public PowerAuthApiAuthentication authenticate(PowerAuthAuthentication authentication) throws PowerAuthAuthenticationException, RemoteException {
        // Handle signature based authentications
        if (authentication instanceof PowerAuthSignatureAuthentication) {
            return validateSignatureAuthentication((PowerAuthSignatureAuthentication) authentication);
        }
        // Handle basic token-based authentications
        else if (authentication instanceof PowerAuthTokenAuthentication) {
            return validateTokenAuthentication((PowerAuthTokenAuthentication) authentication);
        }
        // Return null in case unknown authentication type is provided
        return null;
    }

    /**
     * Validate signature based authentication.
     *
     * @param authentication Signature based authentication object.
     * @return API authentication object in case of successful authentication, null otherwise.
     * @throws PowerAuthAuthenticationException In case signature type is invalid.
     * @throws RemoteException In case remote communication fails.
     */
    private PowerAuthApiAuthentication validateSignatureAuthentication(PowerAuthSignatureAuthentication authentication) throws PowerAuthAuthenticationException, RemoteException {
        if (authentication.getSignatureType() != null) {

            SignatureTypeConverter converter = new SignatureTypeConverter();
            final PowerAuthPortV3ServiceStub.SignatureType signatureType = converter.convertFrom(authentication.getSignatureType());
            if (signatureType == null) {
                logger.warn("Invalid signature type: {}", authentication.getSignatureType());
                throw new PowerAuthSignatureTypeInvalidException();
            }

            PowerAuthPortV3ServiceStub.VerifySignatureRequest soapRequest = new PowerAuthPortV3ServiceStub.VerifySignatureRequest();
            soapRequest.setActivationId(authentication.getActivationId());
            soapRequest.setApplicationKey(authentication.getApplicationKey());
            soapRequest.setSignature(authentication.getSignature());
            soapRequest.setSignatureType(signatureType);
            soapRequest.setSignatureVersion(authentication.getVersion());
            soapRequest.setData(PowerAuthHttpBody.getSignatureBaseString(
                    authentication.getHttpMethod(),
                    authentication.getRequestUri(),
                    authentication.getNonce(),
                    authentication.getData()
            ));

            // In case forced signature version is specified, use it in the SOAP request
            if (authentication.getForcedSignatureVersion() != null) {
                soapRequest.setForcedSignatureVersion(authentication.getForcedSignatureVersion());
            }

            PowerAuthPortV3ServiceStub.VerifySignatureResponse soapResponse = powerAuthClient.verifySignature(soapRequest);

            if (soapResponse.getSignatureValid()) {
                return copyAuthenticationAttributes(soapResponse.getActivationId(), soapResponse.getUserId(),
                        soapResponse.getApplicationId(), Arrays.asList(soapResponse.getApplicationRoles()), Arrays.asList(soapResponse.getActivationFlags()),
                        PowerAuthSignatureTypes.getEnumFromString(soapResponse.getSignatureType().getValue()),
                        authentication.getVersion(), authentication.getHttpHeader());
            } else {
                return null;
            }

        } else {
            return null;
        }
    }

    /**
     * Validate basic token-based authentication.
     *
     * @param authentication Token based authentication object.
     * @return API authentication object in case of successful authentication, null otherwise.
     */
    private PowerAuthApiAuthentication validateTokenAuthentication(PowerAuthTokenAuthentication authentication) throws RemoteException {

        PowerAuthPortV3ServiceStub.ValidateTokenRequest soapRequest = new PowerAuthPortV3ServiceStub.ValidateTokenRequest();
        soapRequest.setTokenId(authentication.getTokenId());
        soapRequest.setTokenDigest(authentication.getTokenDigest());
        soapRequest.setNonce(authentication.getNonce());
        soapRequest.setTimestamp(Long.valueOf(authentication.getTimestamp()));

        try {
            final PowerAuthPortV3ServiceStub.ValidateTokenResponse soapResponse = powerAuthClient.validateToken(soapRequest);
            if (soapResponse.getTokenValid()) {
                return copyAuthenticationAttributes(soapResponse.getActivationId(), soapResponse.getUserId(),
                        soapResponse.getApplicationId(), Arrays.asList(soapResponse.getApplicationRoles()), Arrays.asList(soapResponse.getActivationFlags()),
                        PowerAuthSignatureTypes.getEnumFromString(soapResponse.getSignatureType().getValue()),
                        authentication.getVersion(), authentication.getHttpHeader());
            } else {
                return null;
            }
        } catch (Exception ex) {
            logger.warn("Token validation failed, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        }
    }

    /**
     * Prepare API initialized authentication object with provided authentication attributes.
     *
     * @param activationId Activation ID.
     * @param userId User ID.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles.
     * @param activationFlags Activation flags.
     * @param signatureType Signature Type.
     * @param version PowerAuth protocol version.
     * @param httpHeader Raw PowerAuth HTTP header.
     * @return Initialized instance of API authentication.
     */
    private PowerAuthApiAuthentication copyAuthenticationAttributes(String activationId, String userId, Long applicationId, List<String> applicationRoles,
                                                                    List<String> activationFlags, PowerAuthSignatureTypes signatureType, String version,
                                                                    PowerAuthHttpHeader httpHeader) {
        PowerAuthApiAuthentication apiAuthentication = new PowerAuthApiAuthenticationImpl();
        apiAuthentication.setActivationId(activationId);
        apiAuthentication.setUserId(userId);
        apiAuthentication.setApplicationId(applicationId);
        apiAuthentication.setApplicationRoles(applicationRoles);
        apiAuthentication.setActivationFlags(activationFlags);
        apiAuthentication.setSignatureFactors(signatureType);
        apiAuthentication.setVersion(version);
        apiAuthentication.setHttpHeader(httpHeader);
        return apiAuthentication;
    }

    /**
     * Validate the signature from the PowerAuth HTTP header against the provided HTTP method, request body and URI identifier.
     * Make sure to accept only allowed signatures.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Body of the HTTP request.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedSignatureTypes Allowed types of the signature.
     * @param forcedSignatureVersion Forced signature version during upgrade.
     * @return Instance of a PowerAuthApiAuthenticationImpl on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthentication validateRequestSignature(
            String httpMethod,
            byte[] httpBody,
            String requestUriIdentifier,
            String httpAuthorizationHeader,
            List<PowerAuthSignatureTypes> allowedSignatureTypes,
            Integer forcedSignatureVersion
    ) throws PowerAuthAuthenticationException {

        // Check for HTTP PowerAuth signature header
        if (httpAuthorizationHeader == null || httpAuthorizationHeader.equals("undefined")) {
            logger.warn("Signature HTTP header is missing");
            throw new PowerAuthHeaderMissingException();
        }

        // Parse HTTP header
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(httpAuthorizationHeader);

        // Validate the header
        try {
            PowerAuthSignatureHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Signature HTTP header validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthSignatureInvalidException();
        }

        // Check if the signature type is allowed
        PowerAuthSignatureTypes expectedSignatureType = PowerAuthSignatureTypes.getEnumFromString(header.getSignatureType());
        if (expectedSignatureType == null || !allowedSignatureTypes.contains(expectedSignatureType)) {
            logger.warn("Invalid signature type: {}", expectedSignatureType);
            throw new PowerAuthSignatureTypeInvalidException();
        }

        // Configure PowerAuth authentication object
        PowerAuthSignatureAuthentication powerAuthAuthentication = new PowerAuthSignatureAuthenticationImpl();
        powerAuthAuthentication.setActivationId(header.getActivationId());
        powerAuthAuthentication.setApplicationKey(header.getApplicationKey());
        powerAuthAuthentication.setNonce(BaseEncoding.base64().decode(header.getNonce()));
        powerAuthAuthentication.setSignatureType(header.getSignatureType());
        powerAuthAuthentication.setSignature(header.getSignature());
        powerAuthAuthentication.setHttpMethod(httpMethod);
        powerAuthAuthentication.setRequestUri(requestUriIdentifier);
        powerAuthAuthentication.setData(httpBody);
        powerAuthAuthentication.setVersion(header.getVersion());
        powerAuthAuthentication.setHttpHeader(header);
        powerAuthAuthentication.setForcedSignatureVersion(forcedSignatureVersion);

        // Call the authentication
        PowerAuthApiAuthentication auth;
        try {
            auth = this.authenticate(powerAuthAuthentication);
        } catch (RemoteException ex) {
            logger.warn("Remote communication failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthSignatureErrorException();
        }

        // In case authentication is null, throw PowerAuth exception
        if (auth == null) {
            logger.debug("Signature validation failed");
            throw new PowerAuthSignatureInvalidException();
        }

        return auth;
    }

    @Override
    public PowerAuthApiAuthentication validateToken(String tokenHeader, List<PowerAuthSignatureTypes> allowedSignatureTypes) throws PowerAuthAuthenticationException {

        // Check for HTTP PowerAuth signature header
        if (tokenHeader == null || tokenHeader.equals("undefined")) {
            logger.warn("Token HTTP header is missing");
            throw new PowerAuthHeaderMissingException();
        }

        // Parse HTTP header
        PowerAuthTokenHttpHeader header = new PowerAuthTokenHttpHeader().fromValue(tokenHeader);

        // Validate the header
        try {
            PowerAuthTokenHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Token validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthTokenInvalidException();
        }

        // Prepare authentication object
        PowerAuthTokenAuthentication powerAuthTokenAuthentication = new PowerAuthTokenAuthenticationImpl();
        powerAuthTokenAuthentication.setTokenId(header.getTokenId());
        powerAuthTokenAuthentication.setTokenDigest(header.getTokenDigest());
        powerAuthTokenAuthentication.setNonce(header.getNonce());
        powerAuthTokenAuthentication.setTimestamp(header.getTimestamp());
        powerAuthTokenAuthentication.setVersion(header.getVersion());
        powerAuthTokenAuthentication.setHttpHeader(header);

        // Call the authentication based on token authentication object
        final PowerAuthApiAuthentication auth;
        try {
            auth = this.authenticate(powerAuthTokenAuthentication);
        } catch (RemoteException ex) {
            logger.warn("Remote communication failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthTokenErrorException();
        }

        // In case authentication is null, throw PowerAuth exception
        if (auth == null) {
            logger.debug("Invalid token value");
            throw new PowerAuthTokenInvalidException();
        }

        // Check if the signature type is allowed
        PowerAuthSignatureTypes expectedSignatureType = auth.getSignatureFactors();
        if (expectedSignatureType == null || !allowedSignatureTypes.contains(expectedSignatureType)) {
            logger.warn("Invalid signature type in token validation: {}", expectedSignatureType);
            throw new PowerAuthSignatureTypeInvalidException();
        }

        return auth;
    }

}
