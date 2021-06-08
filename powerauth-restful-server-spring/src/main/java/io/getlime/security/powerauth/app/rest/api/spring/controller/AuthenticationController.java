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
package io.getlime.security.powerauth.app.rest.api.spring.controller;

import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Sample end-point demonstrating how PowerAuth signature validation works.
 *
 * @author Petr Dvorak
 *
 */
@Controller
public class AuthenticationController {

    /**
     * Validate any data sent to this end-point.
     * @param auth Automatically injected PowerAuth authentication object.
     * @return API response with success.
     * @throws PowerAuthAuthenticationException In case any error occurs, including during signature validation.
     */
    @RequestMapping(value = "login", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/login")
    public @ResponseBody ObjectResponse<String> login(PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        if (auth == null || auth.getUserId() == null) {
            throw new PowerAuthSignatureInvalidException();
        }
        return new ObjectResponse<>("Hooray! "
                + " User: " + auth.getUserId()
                + " (activation: " + auth.getActivationId() + ")"
                + " successfully verified via app with ID: " + auth.getApplicationId()
                + " using factor: " + auth.getSignatureFactors()
        );
    }

    /**
     * Validate any data sent to this end-point.
     * @param auth Automatically injected PowerAuth authentication object.
     * @return API response with success.
     * @throws PowerAuthAuthenticationException In case any error occurs, including during signature validation.
     */
    @RequestMapping(value = "login", method = RequestMethod.GET)
    @PowerAuth(resourceId = "/login")
    public @ResponseBody ObjectResponse<String> getLogin(PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        if (auth == null || auth.getUserId() == null) {
            throw new PowerAuthSignatureInvalidException();
        }
        return new ObjectResponse<>("Hooray! User: " + auth.getUserId());
    }

    /**
     * Validate any data sent to this end-point, uses substitutes in resource ID.
     * @param id Identifier - testing object for @PathVariable annotation.
     * @param value Value - testing object for @RequestParam annotation.
     * @param auth Automatically injected PowerAuth authentication object.
     * @return API response with success.
     * @throws PowerAuthAuthenticationException In case any error occurs, including during signature validation.
     */
    @RequestMapping(value = "submit/{id}/test", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/submit/${id}/test?value=${value}")
    public @ResponseBody ObjectResponse<?> dynamicResourceId(@PathVariable("id") String id, @RequestParam("value") String value, PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        if (auth == null || auth.getUserId() == null) {
            throw new PowerAuthSignatureInvalidException();
        }

        final Map<String, String> map = new HashMap<>();
        map.put("user", auth.getUserId());
        map.put("id", id);
        map.put("value", value);

        return new ObjectResponse<>(map);
    }

}
