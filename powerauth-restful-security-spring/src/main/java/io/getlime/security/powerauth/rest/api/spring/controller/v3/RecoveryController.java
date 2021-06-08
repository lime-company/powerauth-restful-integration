/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2019 Wultra s.r.o.
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

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import io.getlime.security.powerauth.rest.api.spring.service.v3.RecoveryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller implementing recovery related end-points from the PowerAuth
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
@RestController
@RequestMapping(value = "/pa/v3/recovery")
public class RecoveryController {

    private static final Logger logger = LoggerFactory.getLogger(RecoveryController.class);

    private final RecoveryService recoveryService;

    /**
     * Service constructor.
     * @param recoveryService Recovery service.
     */
    public RecoveryController(RecoveryService recoveryService) {
        this.recoveryService = recoveryService;
    }

    /**
     * Confirm recovery code.
     * @param request ECIES encrypted request.
     * @param authentication PowerAuth API authentication object.
     * @return ECIES encrypted response.
     * @throws PowerAuthAuthenticationException In case confirm recovery fails.
     */
    @RequestMapping(value = "confirm", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/recovery/confirm", signatureType = {
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE
    })
    public EciesEncryptedResponse confirmRecoveryCode(@RequestBody EciesEncryptedRequest request,
                                                      PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        if (request == null) {
            logger.warn("Invalid request object in confirm recovery");
            throw new PowerAuthInvalidRequestException();
        }
        if (authentication == null || authentication.getActivationId() == null) {
            throw new PowerAuthSignatureInvalidException();
        }
        if (!"3.0".equals(authentication.getVersion()) && !"3.1".equals(authentication.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", authentication.getVersion());
            throw new PowerAuthInvalidRequestException();
        }
        if (request.getNonce() == null && !"3.0".equals(authentication.getVersion())) {
            logger.warn("Missing nonce in ECIES request data");
            throw new PowerAuthInvalidRequestException();
        }
        return recoveryService.confirmRecoveryCode(request, authentication);
    }

}