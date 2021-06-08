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
package io.getlime.security.powerauth.rest.api.spring.controller.v3;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.encryption.EciesEncryptionContext;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthRecoveryException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.spring.service.v3.ActivationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@RestController("activationControllerV3")
@RequestMapping(value = "/pa/v3/activation")
public class ActivationController {

    private static final Logger logger = LoggerFactory.getLogger(ActivationController.class);

    private PowerAuthAuthenticationProvider authenticationProvider;

    private ActivationService activationServiceV3;

    /**
     * Set the activation service via setter injection.
     * @param activationServiceV3 Activation service (v3).
     */
    @Autowired
    public void setActivationServiceV3(ActivationService activationServiceV3) {
        this.activationServiceV3 = activationServiceV3;
    }

    /**
     * Set the authentication provider via setter injection.
     * @param authenticationProvider Authentication provider.
     */
    @Autowired
    public void setAuthenticationProvider(PowerAuthAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    /**
     * Create activation.
     * @param request Encrypted activation layer 1 request.
     * @param eciesContext ECIES encryption context.
     * @return Activation layer 1 response.
     * @throws PowerAuthActivationException In case activation fails.
     * @throws PowerAuthRecoveryException In case recovery PUK is invalid.
     */
    @RequestMapping(value = "create", method = RequestMethod.POST)
    @PowerAuthEncryption(scope = EciesScope.APPLICATION_SCOPE)
    public ActivationLayer1Response createActivation(@EncryptedRequestBody ActivationLayer1Request request,
                                                     EciesEncryptionContext eciesContext) throws PowerAuthActivationException, PowerAuthRecoveryException {
        if (request == null || eciesContext == null) {
            logger.warn("Invalid request in activation create");
            throw new PowerAuthActivationException();
        }
        return activationServiceV3.createActivation(request, eciesContext);
    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     * @throws PowerAuthActivationException In case request fails.
     */
    @RequestMapping(value = "status", method = RequestMethod.POST)
    public ObjectResponse<ActivationStatusResponse> getActivationStatus(@RequestBody ObjectRequest<ActivationStatusRequest> request)
            throws PowerAuthActivationException {
        if (request.getRequestObject() == null || request.getRequestObject().getActivationId() == null) {
            logger.warn("Invalid request object in activation status");
            throw new PowerAuthActivationException();
        }
        ActivationStatusResponse response = activationServiceV3.getActivationStatus(request.getRequestObject());
        return new ObjectResponse<>(response);
    }

    /**
     * Remove activation.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param httpServletRequest HTTP servlet request.
     * @return PowerAuth RESTful response with {@link ActivationRemoveResponse} payload.
     * @throws PowerAuthActivationException In case activation access fails.
     * @throws PowerAuthAuthenticationException In case the signature validation fails.
     */
    @RequestMapping(value = "remove", method = RequestMethod.POST)
    public ObjectResponse<ActivationRemoveResponse> removeActivation(
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader,
            HttpServletRequest httpServletRequest)
            throws PowerAuthActivationException, PowerAuthAuthenticationException {
        byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
        PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature("POST", requestBodyBytes, "/pa/activation/remove", signatureHeader);
        if (apiAuthentication == null || apiAuthentication.getActivationId() == null) {
            logger.debug("Signature validation failed");
            throw new PowerAuthSignatureInvalidException();
        }
        if (!"3.0".equals(apiAuthentication.getVersion()) && !"3.1".equals(apiAuthentication.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", apiAuthentication.getVersion());
            throw new PowerAuthInvalidRequestException();
        }
        ActivationRemoveResponse response = activationServiceV3.removeActivation(apiAuthentication);
        return new ObjectResponse<>(response);
    }
}
