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

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.CreateTokenRequest;
import io.getlime.powerauth.soap.CreateTokenResponse;
import io.getlime.powerauth.soap.PowerAuthPort;
import io.getlime.powerauth.soap.RemoveTokenRequest;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.model.request.TokenCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.TokenRemoveRequest;
import io.getlime.security.powerauth.rest.api.model.response.TokenCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.TokenRemoveResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import io.getlime.security.powerauth.rest.api.spring.converter.SignatureTypeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller responsible for publishing services related to simple token-based authentication.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Controller
@RequestMapping("pa/token")
public class TokenController {

    private final PowerAuthPort powerAuthClient;

    @Autowired
    public TokenController(PowerAuthPort powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @RequestMapping(value = "create", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/token/create", signatureType = {
            PowerAuthSignatureTypes.POSSESSION,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public @ResponseBody ObjectResponse<TokenCreateResponse> createToken(@RequestBody ObjectRequest<TokenCreateRequest> request, PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        try {
            if (authentication != null && authentication.getActivationId() != null) {

                // Fetch activation ID and signature type
                final String activationId = authentication.getActivationId();
                final PowerAuthSignatureTypes signatureFactors = authentication.getSignatureFactors();

                // Fetch data from the request
                final TokenCreateRequest requestObject = request.getRequestObject();
                final String ephemeralPublicKey = requestObject.getEphemeralPublicKey();

                // Prepare a signature type converter
                SignatureTypeConverter converter = new SignatureTypeConverter();

                // Create a token
                final CreateTokenRequest soapRequest = new CreateTokenRequest();
                soapRequest.setActivationId(activationId);
                soapRequest.setEphemeralPublicKey(ephemeralPublicKey);
                soapRequest.setSignatureType(converter.convertFrom(signatureFactors));
                final CreateTokenResponse token = powerAuthClient.createToken(soapRequest);

                // Prepare a response
                final TokenCreateResponse responseObject = new TokenCreateResponse();
                responseObject.setMac(token.getMac());
                responseObject.setEncryptedData(token.getEncryptedData());
                return new ObjectResponse<>(responseObject);
            } else {
                throw new PowerAuthAuthenticationException();
            }
        }  catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PowerAuthAuthenticationException(ex.getMessage());
        }
    }
    
    @RequestMapping(value = "remove", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/token/remove", signatureType = {
            PowerAuthSignatureTypes.POSSESSION,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public @ResponseBody ObjectResponse<TokenRemoveResponse> removeToken(@RequestBody ObjectRequest<TokenRemoveRequest> request, PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        try {
            if (authentication != null && authentication.getActivationId() != null) {

                // Fetch activation ID
                final String activationId = authentication.getActivationId();

                // Fetch token ID from the request
                final TokenRemoveRequest requestObject = request.getRequestObject();
                final String tokenId = requestObject.getTokenId();

                // Remove a token, ignore response, since the endpoint should quietly return
                final RemoveTokenRequest soapRequest = new RemoveTokenRequest();
                soapRequest.setActivationId(activationId);
                soapRequest.setTokenId(tokenId);
                powerAuthClient.removeToken(soapRequest);

                // Prepare a response
                final TokenRemoveResponse responseObject = new TokenRemoveResponse();
                responseObject.setTokenId(requestObject.getTokenId());
                return new ObjectResponse<>(responseObject);

            } else {
                throw new PowerAuthAuthenticationException();
            }
        }  catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PowerAuthAuthenticationException(ex.getMessage());
        }
    }

}
