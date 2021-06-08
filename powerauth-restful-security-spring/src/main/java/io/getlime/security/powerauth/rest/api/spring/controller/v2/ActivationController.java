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
package io.getlime.security.powerauth.rest.api.spring.controller.v2;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
@RestController("activationControllerV2")
@RequestMapping(value = "/pa/activation")
public class ActivationController {

    private static final Logger logger = LoggerFactory.getLogger(ActivationController.class);

    private io.getlime.security.powerauth.rest.api.spring.service.v2.ActivationService activationServiceV2;
    private io.getlime.security.powerauth.rest.api.spring.service.v3.ActivationService activationServiceV3;

    private PowerAuthAuthenticationProvider authenticationProvider;

    /**
     * Set the activation service via setter injection.
     * @param activationServiceV2 Activation service (v2).
     */
    @Autowired
    public void setActivationServiceV2(io.getlime.security.powerauth.rest.api.spring.service.v2.ActivationService activationServiceV2) {
        this.activationServiceV2 = activationServiceV2;
    }

    /**
     * Set the activation service via setter injection.
     * @param activationServiceV3 Activation service (v3).
     */
    @Autowired
    public void setActivationServiceV3(io.getlime.security.powerauth.rest.api.spring.service.v3.ActivationService activationServiceV3) {
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
     * Create a new activation.
     * @param request PowerAuth RESTful request with {@link ActivationCreateRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationCreateResponse} payload.
     * @throws PowerAuthActivationException In case creating activation fails.
     */
    @RequestMapping(value = "create", method = RequestMethod.POST)
    public ObjectResponse<ActivationCreateResponse> createActivation(
            @RequestBody ObjectRequest<ActivationCreateRequest> request
    ) throws PowerAuthActivationException {
        if (request.getRequestObject() == null || request.getRequestObject().getActivationIdShort() == null) {
            logger.warn("Invalid request object in activation create");
            throw new PowerAuthActivationException();
        }
        ActivationCreateResponse response = activationServiceV2.createActivation(request.getRequestObject());
        return new ObjectResponse<>(response);
    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     * @throws PowerAuthActivationException In case request fails.
     */
    @RequestMapping(value = "status", method = RequestMethod.POST)
    public ObjectResponse<ActivationStatusResponse> getActivationStatus(
            @RequestBody ObjectRequest<ActivationStatusRequest> request
    ) throws PowerAuthActivationException {
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
     * @return PowerAuth RESTful response with {@link ActivationRemoveResponse} payload.
     * @throws PowerAuthActivationException In case activation access fails.
     * @throws PowerAuthAuthenticationException In case the signature validation fails.
     */
    @RequestMapping(value = "remove", method = RequestMethod.POST)
    public ObjectResponse<ActivationRemoveResponse> removeActivation(
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader
    ) throws PowerAuthActivationException, PowerAuthAuthenticationException {
        // Request body needs to be set to null because the SDK uses null for the signature, although {} is sent as request body
        PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature("POST", null, "/pa/activation/remove", signatureHeader);
        if (apiAuthentication == null || apiAuthentication.getActivationId() == null) {
            logger.debug("Signature validation failed");
            throw new PowerAuthSignatureInvalidException();
        }
        if (!"2.0".equals(apiAuthentication.getVersion()) && !"2.1".equals(apiAuthentication.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", apiAuthentication.getVersion());
            throw new PowerAuthInvalidRequestException();
        }
        ActivationRemoveResponse response = activationServiceV3.removeActivation(apiAuthentication);
        return new ObjectResponse<>(response);
    }

}
