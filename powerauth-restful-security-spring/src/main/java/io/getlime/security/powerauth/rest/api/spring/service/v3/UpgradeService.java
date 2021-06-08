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
package io.getlime.security.powerauth.rest.api.spring.service.v3;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v3.CommitUpgradeResponse;
import com.wultra.security.powerauth.client.v3.StartUpgradeResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthUpgradeException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.List;

/**
 * Service implementing upgrade functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Service("upgradeServiceV3")
public class UpgradeService {

    private static final Logger logger = LoggerFactory.getLogger(UpgradeService.class);

    private PowerAuthClient powerAuthClient;
    private PowerAuthAuthenticationProvider authenticationProvider;

    /**
     * Set PowerAuth service client via setter injection.
     * @param powerAuthClient PowerAuth service client.
     */
    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Set PowerAuth authentication provider via setter injection.
     * @param authenticationProvider PowerAuth authentication provider.
     */
    @Autowired
    public void setAuthenticationProvider(PowerAuthAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    /**
     * Start upgrade of activation to version 3.
     * @param request ECIES encrypted upgrade start request.
     * @param header PowerAuth encryption HTTP header.
     * @return ECIES encrypted upgrade activation response.
     * @throws PowerAuthUpgradeException In case upgrade start fails.
     */
    public EciesEncryptedResponse upgradeStart(EciesEncryptedRequest request, PowerAuthEncryptionHttpHeader header)
            throws PowerAuthUpgradeException {

        try {
            // Fetch data from the request
            final String ephemeralPublicKey = request.getEphemeralPublicKey();
            final String encryptedData = request.getEncryptedData();
            final String mac = request.getMac();
            final String nonce = request.getNonce();

            // Get ECIES headers
            final String activationId = header.getActivationId();
            final String applicationKey = header.getApplicationKey();

            // Start upgrade on PowerAuth server
            final StartUpgradeResponse upgradeResponse = powerAuthClient.startUpgrade(activationId, applicationKey, ephemeralPublicKey, encryptedData, mac, nonce);

            // Prepare a response
            final EciesEncryptedResponse response = new EciesEncryptedResponse();
            response.setMac(upgradeResponse.getMac());
            response.setEncryptedData(upgradeResponse.getEncryptedData());
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth upgrade start failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }
    }

    /**
     * Commit upgrade of activation to version 3.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param httpServletRequest HTTP servlet request.
     * @return Commit upgrade response.
     * @throws PowerAuthAuthenticationException in case authentication fails.
     * @throws PowerAuthUpgradeException In case upgrade commit fails.
     */
    public Response upgradeCommit(String signatureHeader,
                                  HttpServletRequest httpServletRequest)
            throws PowerAuthAuthenticationException, PowerAuthUpgradeException {

        try {
            // Extract request body
            final byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
            if (requestBodyBytes == null || requestBodyBytes.length == 0) {
                // Expected request body is {}, do not accept empty body
                logger.warn("Empty request body");
                throw new PowerAuthInvalidRequestException();
            }

            // Verify signature, force signature version during upgrade to version 3
            final List<PowerAuthSignatureTypes> allowedSignatureTypes = Collections.singletonList(PowerAuthSignatureTypes.POSSESSION);
            final PowerAuthApiAuthentication authentication = authenticationProvider.validateRequestSignature("POST", requestBodyBytes, "/pa/upgrade/commit", signatureHeader, allowedSignatureTypes, 3);

            // In case signature verification fails, upgrade fails, too
            if (authentication == null || authentication.getActivationId() == null) {
                logger.debug("Signature validation failed");
                throw new PowerAuthSignatureInvalidException();
            }

            // Get signature HTTP headers
            final String activationId = authentication.getActivationId();
            final PowerAuthSignatureHttpHeader httpHeader = (PowerAuthSignatureHttpHeader) authentication.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();

            // Commit upgrade on PowerAuth server
            final CommitUpgradeResponse upgradeResponse = powerAuthClient.commitUpgrade(activationId, applicationKey);

            if (upgradeResponse.isCommitted()) {
                return new Response();
            } else {
                logger.debug("Upgrade commit failed");
                throw new PowerAuthUpgradeException();
            }
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("PowerAuth upgrade commit failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }
    }
}
