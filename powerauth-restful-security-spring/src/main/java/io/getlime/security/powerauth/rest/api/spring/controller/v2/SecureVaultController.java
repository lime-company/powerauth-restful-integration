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
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.v2.VaultUnlockRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.VaultUnlockResponse;
import io.getlime.security.powerauth.rest.api.spring.service.v2.SecureVaultService;
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
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("secureVaultControllerV2")
@RequestMapping(value = "/pa/vault")
public class SecureVaultController {

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultController.class);

    private SecureVaultService secureVaultServiceV2;

    /**
     * Set the secure vault service via setter injection.
     * @param secureVaultServiceV2 Secure vault service.
     */
    @Autowired
    public void setSecureVaultServiceV2(SecureVaultService secureVaultServiceV2) {
        this.secureVaultServiceV2 = secureVaultServiceV2;
    }

    /**
     * Request the vault unlock key.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param request Vault unlock request data.
     * @param httpServletRequest HTTP servlet request.
     * @return PowerAuth RESTful response with {@link VaultUnlockResponse} payload.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     * @throws PowerAuthSecureVaultException In case unlocking the vault fails.
     */
    @RequestMapping(value = "unlock", method = RequestMethod.POST)
    public ObjectResponse<VaultUnlockResponse> unlockVault(
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME, defaultValue = "unknown") String signatureHeader,
            @RequestBody(required=false) ObjectRequest<VaultUnlockRequest> request,
            HttpServletRequest httpServletRequest)
            throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {

        // Request object is not validated - it is optional for version 2

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

        if (!"2.0".equals(header.getVersion()) && !"2.1".equals(header.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", header.getVersion());
            throw new PowerAuthInvalidRequestException();
        }

        VaultUnlockResponse response = secureVaultServiceV2.vaultUnlock(signatureHeader, request.getRequestObject(), httpServletRequest);
        return new ObjectResponse<>(response);
    }

}
