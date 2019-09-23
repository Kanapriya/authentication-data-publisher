/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.data.publisher.application.authentication.internal.AuthenticationDataPublisherDataHolder;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.custom.data.publisher.local.CustomPasswordGrantPublisher;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Collections;

/**
 * @scr.component name="org.wso2.custom.data.publisher.local.component" immediate="true"
 * @scr.reference name="org.wso2.carbon.event.stream.core"
 * interface="org.wso2.carbon.event.stream.core.EventStreamService"
 * cardinality="1..1" policy="dynamic"  bind="setEventStreamService"
 * unbind="unsetEventStreamService"
 * @scr.reference name="org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor"
 * interface="org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor"
 * cardinality="0..n" policy="dynamic"
 * bind="setAuthEventInterceptor"
 * unbind="unsetOauthEventInterceptor"
 * @scr.reference name="org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent"
 * interface="org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent"
 * cardinality="1..1" policy="dynamic"
 * bind="setIdentityCoreInitializedEvent"
 * unbind="unsetIdentityCoreInitializedEvent"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 */
public class CustomAuthenticationDataPublisherServiceComponent {

    private static Log log = LogFactory.getLog(CustomAuthenticationDataPublisherServiceComponent.class);


    protected void activate(ComponentContext ctxt) {
        try {

            CustomPasswordGrantPublisher dataPublisher1 = new CustomPasswordGrantPublisher();
            ctxt.getBundleContext().registerService(OAuthEventInterceptor.class.getName(), dataPublisher1, null);
            log.info("================ CustomPasswordGrantDataPublisherImpl bundle is activated");
        } catch (Throwable e) {
            log.error("================ CustomPasswordGrantDataPublisherImpl bundle activation Failed", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("================ CustomPasswordGrantDataPublisherImpl bundle is deactivated");
        }
    }


    protected void setEventStreamService(EventStreamService publisherService) {
        if(log.isDebugEnabled()) {
            log.debug("Registering EventStreamService");
        }
        CustomOAuthDataPublisherServiceHolder.getInstance().setPublisherService(publisherService);
    }

    protected void unsetEventStreamService(EventStreamService publisherService) {
        if(log.isDebugEnabled()) {
            log.debug("Un-registering EventStreamService");
        }
        CustomOAuthDataPublisherServiceHolder.getInstance().setPublisherService(null);
    }

    protected void setAuthEventInterceptor(OAuthEventInterceptor oAuthEventInterceptor) {

        if (oAuthEventInterceptor == null) {
            log.warn("Null OAuthEventListener received, hence not registering");
            return;
        }

        if (OAuthConstants.OAUTH_INTERCEPTOR_PROXY.equalsIgnoreCase(oAuthEventInterceptor.getName())) {
            log.debug("Oauth intercepter Proxy is getting registered, Hence skipping");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Setting OAuthEventListener :" + oAuthEventInterceptor.getClass().getName());
        }
        CustomOAuthDataPublisherServiceHolder.getInstance().addOauthEventListener(oAuthEventInterceptor);
        Collections.sort(CustomOAuthDataPublisherServiceHolder.getInstance().getOAuthEventInterceptors(),
                new HandlerComparator());
        Collections.reverse(CustomOAuthDataPublisherServiceHolder.getInstance().getOAuthEventInterceptors());
    }

    protected void unsetOauthEventInterceptor(OAuthEventInterceptor oAuthEventInterceptor) {

        if (oAuthEventInterceptor == null) {
            log.warn("Null Oauth event interceptor received, hence not un-registering");
            return;
        }

        if (OAuthConstants.OAUTH_INTERCEPTOR_PROXY.equalsIgnoreCase(oAuthEventInterceptor.getName())) {
            log.debug("Proxy is un-registering, Hence skipping");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Un-setting oAuthEventInterceptor:" + oAuthEventInterceptor.getClass().getName());
        }
        CustomOAuthDataPublisherServiceHolder.getInstance().removeOauthEventListener(oAuthEventInterceptor);
    }

    protected void setIdentityCoreInitializedEvent(IdentityCoreInitializedEvent identityCoreInitializedEvent) {

        // Nothing to implement
    }

    protected void unsetIdentityCoreInitializedEvent(IdentityCoreInitializedEvent identityCoreInitializedEvent) {

        // Nothing to implement
    }

    protected void setRegistryService(RegistryService registryService) {

        CustomOAuthDataPublisherServiceHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        CustomOAuthDataPublisherServiceHolder.getInstance().setRegistryService(null);
    }

    protected void setRealmService(RealmService realmService) {

        CustomOAuthDataPublisherServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        CustomOAuthDataPublisherServiceHolder.getInstance().setRealmService(null);

    }
}
