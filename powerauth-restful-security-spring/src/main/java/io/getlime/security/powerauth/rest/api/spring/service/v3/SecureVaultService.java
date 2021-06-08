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

import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v3.SignatureType;
import com.wultra.security.powerauth.client.v3.VaultUnlockResponse;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureTypeInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.converter.v3.SignatureTypeConverter;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

/**
 * Service implementing secure vault functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Service("secureVaultServiceV3")
public class SecureVaultService {

    private PowerAuthClient powerAuthClient;

    private PowerAuthAuthenticationProvider authenticationProvider;

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultService.class);

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
     * Unlock secure vault.
     * @param header PowerAuth signature HTTP header.
     * @param request ECIES encrypted vault unlock request.
     * @param httpServletRequest HTTP servlet request.
     * @return ECIES encrypted vault unlock response.
     * @throws PowerAuthSecureVaultException In case vault unlock request fails.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     */
    public EciesEncryptedResponse vaultUnlock(PowerAuthSignatureHttpHeader header,
                                              EciesEncryptedRequest request,
                                              HttpServletRequest httpServletRequest) throws PowerAuthSecureVaultException, PowerAuthAuthenticationException {
        try {
            final SignatureTypeConverter converter = new SignatureTypeConverter();

            final String activationId = header.getActivationId();
            final String applicationKey = header.getApplicationKey();
            final String signature = header.getSignature();
            final SignatureType signatureType = converter.convertFrom(header.getSignatureType());
            if (signatureType == null) {
                logger.warn("Invalid signature type: {}", header.getSignatureType());
                throw new PowerAuthSignatureTypeInvalidException();
            }
            final String signatureVersion = header.getVersion();
            final String nonce = header.getNonce();

            // Fetch data from the request
            final String ephemeralPublicKey = request.getEphemeralPublicKey();
            final String encryptedData = request.getEncryptedData();
            final String mac = request.getMac();
            final String eciesNonce = request.getNonce();

            // Prepare data for signature to allow signature verification on PowerAuth server
            final byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
            final String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", BaseEncoding.base64().decode(nonce), requestBodyBytes);

            // Verify signature and get encrypted vault encryption key from PowerAuth server
            final VaultUnlockResponse paResponse = powerAuthClient.unlockVault(activationId, applicationKey, signature,
                    signatureType, signatureVersion, data, ephemeralPublicKey, encryptedData, mac, eciesNonce);

            if (!paResponse.isSignatureValid()) {
                logger.debug("Signature validation failed");
                throw new PowerAuthSignatureInvalidException();
            }

            return new EciesEncryptedResponse(paResponse.getEncryptedData(), paResponse.getMac());
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("PowerAuth vault unlock failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthSecureVaultException();
        }
    }
}
