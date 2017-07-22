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
package io.getlime.security.powerauth.app.rest.api.spring.controller;

import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Sample end-point demonstrating how PowerAuth signature validation works.
 *
 * @author Petr Dvorak
 *
 */
@Controller
@RequestMapping(value = "pa/signature")
public class AuthenticationController {

    /**
     * Validate any data sent to this end-point.
     * @param auth Automatically injected PowerAuth authetnication object.
     * @return API response with success.
     * @throws Exception In case any error occurs, including during signature validation.
     */
    @RequestMapping(value = "validate", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/signature/validate")
    public @ResponseBody ObjectResponse<String> login(PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        if (auth != null && auth.getUserId() != null) {
            return new ObjectResponse<>("Hooray! User: " + auth.getUserId());
        } else {
            throw new PowerAuthAuthenticationException("Login failed");
        }

    }

    /**
     * Validate any data sent to this end-point.
     * @param auth Automatically injected PowerAuth authentication object.
     * @return API response with success.
     * @throws Exception In case any error occurs, including during signature validation.
     */
    @RequestMapping(value = "validate", method = RequestMethod.GET)
    @PowerAuth(resourceId = "/pa/signature/validate")
    public @ResponseBody ObjectResponse<String> getLogin(PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        if (auth != null && auth.getUserId() != null) {
            return new ObjectResponse<>("Hooray! User: " + auth.getUserId());
        } else {
            throw new PowerAuthAuthenticationException("Login failed");
        }

    }

}
