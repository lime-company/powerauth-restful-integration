/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2019 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.jaxrs.exception;

import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthRecoveryException;
import io.getlime.security.powerauth.rest.api.model.exception.RecoveryErrorResponse;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Class responsible for PowerAuth Standard RESTful API exception handling for
 * exceptions that are raised during the recovery phase.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthRecoveryExceptionResolver implements ExceptionMapper<PowerAuthRecoveryException> {

    @Override
    public Response toResponse(PowerAuthRecoveryException ex) {
        return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(new RecoveryErrorResponse(ex.getErrorCode(), ex.getMessage(), ex.getCurrentRecoveryPukIndex()))
                .build();
    }
}
