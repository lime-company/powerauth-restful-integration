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

import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.service.v3.SecureVaultService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * Controller implementing secure vault related end-points from the
 * PowerAuth Standard API.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("secureVaultControllerV3")
@RequestMapping(value = "/pa/v3/vault")
public class SecureVaultController {

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultController.class);

    private SecureVaultService secureVaultServiceV3;

    /**
     * Set the secure vault service via setter injection.
     * @param secureVaultServiceV3 Secure vault service.
     */
    @Autowired
    public void setSecureVaultServiceV3(SecureVaultService secureVaultServiceV3) {
        this.secureVaultServiceV3 = secureVaultServiceV3;
    }

    /**
     * Request the vault unlock key.
     *
     * @param signatureHeader PowerAuth HTTP signature header.
     * @param request Request object encrypted by ECIES.
     * @param httpServletRequest HTTP servlet request.
     * @return Response object encrypted by ECIES.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     * @throws PowerAuthSecureVaultException In case unlocking the vault fails.
     */
    @RequestMapping(value = "unlock", method = RequestMethod.POST)
    public EciesEncryptedResponse unlockVault(
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME, defaultValue = "unknown") String signatureHeader,
            @RequestBody EciesEncryptedRequest request,
            HttpServletRequest httpServletRequest)
            throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {

        if (request == null) {
            logger.warn("Invalid request object in vault unlock");
            throw new PowerAuthInvalidRequestException();
        }

        // Parse the header
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHeader);

        // Validate the header
        try {
            PowerAuthSignatureHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Signature HTTP header validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthSignatureInvalidException();
        }

        if (!"3.0".equals(header.getVersion()) && !"3.1".equals(header.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", header.getVersion());
            throw new PowerAuthInvalidRequestException();
        }
        if (request.getNonce() == null && !"3.0".equals(header.getVersion())) {
            logger.warn("Missing nonce in ECIES request data");
            throw new PowerAuthInvalidRequestException();
        }

        return secureVaultServiceV3.vaultUnlock(header, request, httpServletRequest);
    }

}
