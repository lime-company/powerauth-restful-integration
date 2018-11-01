/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.controller;

import com.google.common.io.BaseEncoding;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.PowerAuthPort;
import io.getlime.powerauth.soap.SignatureType;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.base.filter.PowerAuthRequestFilterBase;
import io.getlime.security.powerauth.rest.api.model.request.VaultUnlockRequest;
import io.getlime.security.powerauth.rest.api.model.response.VaultUnlockResponse;
import io.getlime.security.powerauth.rest.api.spring.converter.SignatureTypeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * Controller implementing secure vault related end-points from the
 * PowerAuth Standard API.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Controller
@RequestMapping(value = "/pa/vault")
public class SecureVaultController {

    private PowerAuthPort powerAuthClient;

    @Autowired
    public void setPowerAuthClient(PowerAuthPort powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
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
    public @ResponseBody ObjectResponse<VaultUnlockResponse> unlockVault(
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME, defaultValue = "unknown") String signatureHeader,
            @RequestBody(required=false) ObjectRequest<VaultUnlockRequest> request,
            HttpServletRequest httpServletRequest)
            throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {

        try {
            // Parse the header
            PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHeader);

            // Validate the header
            try {
                PowerAuthSignatureHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException e) {
                throw new PowerAuthAuthenticationException(e.getMessage());
            }

            SignatureTypeConverter converter = new SignatureTypeConverter();

            String activationId = header.getActivationId();
            String applicationId = header.getApplicationKey();
            String signature = header.getSignature();
            SignatureType signatureType = converter.convertFrom(header.getSignatureType());
            String nonce = header.getNonce();

            String reason = null;
            byte[] requestBodyBytes;

            if ("2.0".equals(header.getVersion())) {
                // Version 2.0 requires null data in signature for vault unlock.
                requestBodyBytes = null;
            } else {
                // Version 2.1 or higher requires request data in signature (POST request body) for vault unlock.
                if (request != null) {
                    // Send vault unlock reason, in case it is available.
                    VaultUnlockRequest vaultUnlockRequest = request.getRequestObject();
                    if (vaultUnlockRequest != null && vaultUnlockRequest.getReason() != null) {
                        reason = vaultUnlockRequest.getReason();
                    }
                }

                // Use POST request body as data for signature.
                String requestBodyString = ((String) httpServletRequest.getAttribute(PowerAuthRequestFilterBase.POWERAUTH_SIGNATURE_BASE_STRING));
                requestBodyBytes = requestBodyString == null ? null : BaseEncoding.base64().decode(requestBodyString);
            }

            String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", BaseEncoding.base64().decode(nonce), requestBodyBytes);

            final io.getlime.powerauth.soap.VaultUnlockRequest soapRequest = new io.getlime.powerauth.soap.VaultUnlockRequest();
            soapRequest.setActivationId(activationId);
            soapRequest.setActivationId(applicationId);
            soapRequest.setData(data);
            soapRequest.setSignature(signature);
            soapRequest.setSignatureType(signatureType);
            soapRequest.setReason(reason);
            io.getlime.powerauth.soap.VaultUnlockResponse soapResponse = powerAuthClient.vaultUnlock(soapRequest);

            if (!soapResponse.isSignatureValid()) {
                throw new PowerAuthAuthenticationException();
            }

            VaultUnlockResponse response = new VaultUnlockResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedVaultEncryptionKey(soapResponse.getEncryptedVaultEncryptionKey());

            return new ObjectResponse<>(response);
        } catch (Exception ex) {
            if (PowerAuthAuthenticationException.class.equals(ex.getClass())) {
                throw ex;
            } else {
                throw new PowerAuthSecureVaultException();
            }
        }
    }

}
