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
package io.getlime.security.powerauth.rest.api.spring.application;

import io.getlime.security.powerauth.rest.api.spring.model.ActivationContext;

import java.util.Map;

/**
 * Interface providing method for PowerAuth behavior high-level customization.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public interface PowerAuthApplicationConfiguration {

    /**
     * In order to minimize number of up-front request, /pa/activation/status end-point may return
     * any custom state-less object with an information about the service (such as current timestamp,
     * service outage info, etc.), or an activation-scoped object. When fetching the activation scoped
     * object, developers should pay attention to the performance. Status endpoint is a frequently called
     * endpoint and hence any queries should use low-latency services. Default implementation may simply
     * return null.
     *
     * @param activationContext Activation context.
     * @return Custom object with state-less information about the API server status.
     */
    Map<String, Object> statusServiceCustomObject(ActivationContext activationContext);

}
