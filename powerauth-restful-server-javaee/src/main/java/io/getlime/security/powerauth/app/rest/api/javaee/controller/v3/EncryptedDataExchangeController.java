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
package io.getlime.security.powerauth.app.rest.api.javaee.controller.v3;

import io.getlime.security.powerauth.app.rest.api.javaee.model.request.DataExchangeRequest;
import io.getlime.security.powerauth.app.rest.api.javaee.model.response.DataExchangeResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.encryption.EciesEncryptionContext;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthEncryptionProvider;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Sample end-point demonstrating how to receive and send encrypted data.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 * <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Path("/exchange")
@Produces(MediaType.APPLICATION_JSON)
public class EncryptedDataExchangeController {

    @Inject
    private PowerAuthEncryptionProvider encryptionProvider;

    @Context
    private HttpServletRequest httpServletRequest;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    /**
     * Sample encrypted data exchange in application scope.
     *
     * @return ECIES encrypted response.
     * @throws PowerAuthEncryptionException In case encryption fails.
     */
    @POST
    @Path("v3/application")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public EciesEncryptedResponse exchangeInApplicationScope() throws PowerAuthEncryptionException {
        // Decrypt request
        PowerAuthEciesEncryption<DataExchangeRequest> eciesEncryption = encryptionProvider.decryptRequest(httpServletRequest,
                DataExchangeRequest.class, EciesScope.APPLICATION_SCOPE);
        DataExchangeRequest request = eciesEncryption.getRequestObject();
        EciesEncryptionContext eciesContext = eciesEncryption.getContext();

        // Prepare response object
        DataExchangeResponse exchangeResponse = new DataExchangeResponse("Server successfully decrypted signed data: " + (request == null ? "''" : request.getData()) + ", scope: " + eciesContext.getEciesScope());

        // Encrypt response
        return encryptionProvider.encryptResponse(exchangeResponse, eciesEncryption);
    }


    /**
     * Sample encrypted data exchange in activation scope.
     *
     * @return ECIES encrypted response.
     * @throws PowerAuthEncryptionException In case encryption fails.
     */
    @POST
    @Path("v3/activation")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public EciesEncryptedResponse exchangeInActivationScope() throws PowerAuthEncryptionException {
        // Decrypt request
        PowerAuthEciesEncryption<DataExchangeRequest> eciesEncryption = encryptionProvider.decryptRequest(httpServletRequest,
                DataExchangeRequest.class, EciesScope.ACTIVATION_SCOPE);
        DataExchangeRequest request = eciesEncryption.getRequestObject();
        EciesEncryptionContext eciesContext = eciesEncryption.getContext();

        // Prepare response object
        DataExchangeResponse exchangeResponse = new DataExchangeResponse("Server successfully decrypted signed data: " + (request == null ? "''" : request.getData()) + ", scope: " + eciesContext.getEciesScope());

        // Encrypt response
        return encryptionProvider.encryptResponse(exchangeResponse, eciesEncryption);
    }

    /**
     * Sample encrypted data exchange in activation scope.
     *
     * @return ECIES encrypted response.
     * @throws PowerAuthAuthenticationException In case signature validation fails
     * @throws PowerAuthEncryptionException In case encryption fails.
     */
    @POST
    @Path("v3/signed")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public EciesEncryptedResponse exchangeSignedAndEncryptedData(@HeaderParam(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader) throws PowerAuthEncryptionException, PowerAuthAuthenticationException {
        // Decrypt request
        PowerAuthEciesEncryption<DataExchangeRequest> eciesEncryption = encryptionProvider.decryptRequest(httpServletRequest,
                DataExchangeRequest.class, EciesScope.ACTIVATION_SCOPE);
        DataExchangeRequest request = eciesEncryption.getRequestObject();

        // Verify PowerAuth signature
        PowerAuthApiAuthentication auth = authenticationProvider.validateRequestSignature(
                httpServletRequest,
                "/exchange/v3/signed",
                authHeader
        );

        if (auth != null && auth.getUserId() != null) {
            // Prepare response object
            DataExchangeResponse exchangeResponse = new DataExchangeResponse("Server successfully decrypted data and verified signature, request data: " + (request == null ? "''" : request.getData()) + ", user ID: " + auth.getUserId());

            // Encrypt response
            return encryptionProvider.encryptResponse(exchangeResponse, eciesEncryption);
        } else {
            throw new PowerAuthAuthenticationException("Authentication failed.");
        }
    }

}
