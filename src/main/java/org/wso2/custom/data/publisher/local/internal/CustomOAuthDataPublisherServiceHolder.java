/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.custom.data.publisher.local.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;

public class CustomOAuthDataPublisherServiceHolder {

    private EventStreamService publisherService;
    private RegistryService registryService;
    private static RealmService realmService;

    // Keeps a sorted list of OauthEventInterceptors
    private List<OAuthEventInterceptor> oAuthEventInterceptors;

    private static CustomOAuthDataPublisherServiceHolder serviceHolder = new CustomOAuthDataPublisherServiceHolder();

    private static Log log = LogFactory.getLog(CustomOAuthDataPublisherServiceHolder.class);

    private CustomOAuthDataPublisherServiceHolder() {

    }

    public static CustomOAuthDataPublisherServiceHolder getInstance() {

        return serviceHolder;
    }

    public EventStreamService getPublisherService() {

        return publisherService;
    }

    public void setPublisherService(EventStreamService publisherService) {

        this.publisherService = publisherService;
    }

    public void addOauthEventListener(OAuthEventInterceptor oAuthEventListener) {

        if (oAuthEventInterceptors == null) {
            oAuthEventInterceptors = new ArrayList<>();
        }
        oAuthEventInterceptors.add(oAuthEventListener);
    }

    public void removeOauthEventListener(OAuthEventInterceptor OAuthEventListener) {

        if (oAuthEventInterceptors != null && OAuthEventListener != null) {
            boolean isRemoved = oAuthEventInterceptors.remove(OAuthEventListener);
            if (!isRemoved) {
                log.warn(OAuthEventListener.getClass().getName() + " had not been registered as a listener");
            }
        }
    }

    public List<OAuthEventInterceptor> getOAuthEventInterceptors() {

        if (oAuthEventInterceptors == null) {
            oAuthEventInterceptors = new ArrayList<>();
        }
        return oAuthEventInterceptors;
    }

    public void setRegistryService(RegistryService registryService) {

        this.registryService = registryService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public RegistryService getRegistryService() {

        return registryService;
    }

    public RealmService getRealmService() {

        return realmService;
    }
}
