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
package io.getlime.security.powerauth.rest.api.spring.filter;

import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthRequestCanonizationUtils;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.model.PowerAuthRequestBody;
import io.getlime.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Class implementing filter for extracting request body from HTTP servlet request.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthRequestFilterBase {

    /**
     * Extract request body from HTTP servlet request. Different logic is used for GET and for all other HTTP methods.
     *
     * @param httpRequest HTTP servlet request.
     * @return Resettable HTTP servlet request.
     * @throws IOException In case request body extraction fails.
     */
    public static ResettableStreamHttpServletRequest filterRequest(HttpServletRequest httpRequest) throws IOException {
        final ResettableStreamHttpServletRequest resettableRequest = new ResettableStreamHttpServletRequest(httpRequest);

        if (httpRequest.getHeader(PowerAuthSignatureHttpHeader.HEADER_NAME) == null && httpRequest.getHeader(PowerAuthEncryptionHttpHeader.HEADER_NAME) == null) {
            // PowerAuth HTTP headers are not present, store empty request body in request attribute
            resettableRequest.setAttribute(
                    PowerAuthRequestObjects.REQUEST_BODY,
                    new PowerAuthRequestBody()
            );
            return resettableRequest;
        }

        if (httpRequest.getMethod().equalsIgnoreCase("GET")) {
            // Parse the query parameters
            String queryString = httpRequest.getQueryString();

            if (queryString != null && queryString.length() > 0) {

                // Decode the query string
                queryString = URLDecoder.decode(queryString, "UTF-8");

                // Get the canonized form
                final String signatureBaseStringData = PowerAuthRequestCanonizationUtils.canonizeGetParameters(queryString);

                // Pass the signature base string as the request attribute
                if (signatureBaseStringData != null) {
                    resettableRequest.setAttribute(
                            PowerAuthRequestObjects.REQUEST_BODY,
                            new PowerAuthRequestBody(signatureBaseStringData.getBytes(StandardCharsets.UTF_8))
                    );
                } else {
                    // Store empty request body in request attribute
                    resettableRequest.setAttribute(
                            PowerAuthRequestObjects.REQUEST_BODY,
                            new PowerAuthRequestBody()
                    );
                }
            } else {
                // Store empty request body in request attribute
                resettableRequest.setAttribute(
                        PowerAuthRequestObjects.REQUEST_BODY,
                        new PowerAuthRequestBody()
                );
            }

        } else { // ... handle POST, PUT, DELETE, ... method

            // Get the request body and pass it as the signature base string as the request attribute
            final byte[] body = resettableRequest.getRequestBody();
            if (body != null) {
                resettableRequest.setAttribute(
                        PowerAuthRequestObjects.REQUEST_BODY,
                        new PowerAuthRequestBody(body)
                );
            } else {
                // Store empty request body in request attribute
                resettableRequest.setAttribute(
                        PowerAuthRequestObjects.REQUEST_BODY,
                        new PowerAuthRequestBody()
                );
            }
        }
        return resettableRequest;
    }

}
