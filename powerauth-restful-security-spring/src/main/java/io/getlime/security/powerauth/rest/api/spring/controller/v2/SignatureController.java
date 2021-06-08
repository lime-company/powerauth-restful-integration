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

import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * End-point for validating signatures.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@RestController("signatureControllerV2")
@RequestMapping(value = "/pa/signature")
public class SignatureController {

    private static final Logger logger = LoggerFactory.getLogger(SignatureController.class);

    /**
     * Validate signature by validating any data sent in request to this end-point.
     * @param auth Automatically injected PowerAuth authentication object.
     * @return API response with success.
     * @throws PowerAuthAuthenticationException In case any error occurs, including signature validation errors.
     */
    @RequestMapping(value = "validate", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
    @PowerAuth(resourceId = "/pa/signature/validate", signatureType = {
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public Response validateSignature(PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {

        if (auth == null || auth.getActivationId() == null) {
            logger.debug("Signature validation failed");
            throw new PowerAuthSignatureInvalidException();
        }
        if (!"2.0".equals(auth.getVersion()) && !"2.1".equals(auth.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", auth.getVersion());
            throw new PowerAuthInvalidRequestException();
        }
        return new Response();
    }

}
