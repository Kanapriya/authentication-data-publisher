package org.wso2.custom.data.publisher.local;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherConstants;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.oauth.model.TokenData;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.*;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;

import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.custom.data.publisher.local.internal.CustomOAuthDataPublisherServiceHolder;

import java.util.*;

public class CustomPasswordGrantPublisher  extends AbstractIdentityHandler implements OAuthEventInterceptor {

    public static final Log LOG = LogFactory.getLog(CustomPasswordGrantPublisher.class);

    private static final String PASSWORD_GRANT = "password";

    private static final String TOKEN_ISSUE_EVENT_STREAM_NAME = "org.wso2.is.analytics.stream.OverallAuthentication:1.0.0";


    public CustomPasswordGrantPublisher() {
        super();
    }

    @Override
    public void onPreTokenIssue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, OAuthTokenReqMessageContext oAuthTokenReqMessageContext, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO,
                                 OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx,
                                 Map<String, Object> params) throws IdentityOAuth2Exception {

        TokenData tokenData = new TokenData();
        if (!isPasswordGrant(tokenReqDTO)) {
            return;
        }

        String requestType = "N/A";
        String serviceProvider = "N/A";
        String authenticatedSubjectIdentifier = "N/A";
        String authenticatedUserStoreDomain = "N/A";
        String authenticatedUserTenantDomain = "N/A";
        String requestInitiator;
        String[] publishingTenantDomains = null;

        if (tokReqMsgCtx.getProperty("OAuthAppDO") instanceof OAuthAppDO) {
            OAuthAppDO oAuthAppDO = (OAuthAppDO) tokReqMsgCtx.getProperty("OAuthAppDO");
            requestType = getRequestType(tokReqMsgCtx);
            serviceProvider = oAuthAppDO.getApplicationName();
        }

        requestInitiator = getResourceOwnerUsername(tokReqMsgCtx);
        if (isTokenRequestSuccessful(tokReqMsgCtx)) {
            authenticatedSubjectIdentifier = getAuthenticatedSubjectIdentifier(tokReqMsgCtx);
            authenticatedUserStoreDomain = tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain();
            authenticatedUserTenantDomain = tokReqMsgCtx.getAuthorizedUser().getTenantDomain();
        }
        if (authenticatedSubjectIdentifier!= null) {
            tokenData.setIsSuccess(true);
            tokenData.setUser(requestInitiator);
            tokenData.setUserStoreDomain(authenticatedUserStoreDomain);
            tokenData.setTenantDomain(authenticatedUserTenantDomain);
            publishingTenantDomains = OAuthDataPublisherUtils.getTenantDomains(tokenReqDTO.getTenantDomain(),
                    authenticatedUserTenantDomain);

        }

        tokenData.setIssuedTime(tokReqMsgCtx.getAccessTokenIssuedTime());
        tokenData.setRefreshTokenValidityMillis(tokReqMsgCtx.getRefreshTokenvalidityPeriod());

        tokenData.setGrantType(tokenReqDTO.getGrantType());
        tokenData.setClientId(tokenReqDTO.getClientId());
        tokenData.setTokenId(tokenRespDTO.getTokenId());
        StringBuilder unauthzScopes = new StringBuilder();
        List<String> requestedScopes = new LinkedList(Arrays.asList(tokenReqDTO.getScope()));
        List<String> grantedScopes;

        if (tokenRespDTO.getAuthorizedScopes() != null && StringUtils.isNotBlank(tokenRespDTO.getAuthorizedScopes())) {
            grantedScopes = Arrays.asList(tokenRespDTO.getAuthorizedScopes().split(" "));
        } else {
            grantedScopes = Collections.emptyList();
        }
        requestedScopes.removeAll(grantedScopes);
        for (String scope : requestedScopes) {
            unauthzScopes.append(scope).append(" ");
        }

        // In a case if the authenticated user is not preset, publish event to sp tenant domain
        if (publishingTenantDomains == null) {
            publishingTenantDomains = OAuthDataPublisherUtils.getTenantDomains(tokenReqDTO.getTenantDomain(), null);
        }
        tokenData.setAuthzScopes(tokenRespDTO.getAuthorizedScopes());
        tokenData.setUnAuthzScopes(unauthzScopes.toString());
        tokenData.setAccessTokenValidityMillis(tokenRespDTO.getExpiresInMillis());

        tokenData.addParameter(OAuthDataPublisherConstants.TENANT_ID, publishingTenantDomains);
        this.publishTokenIssueEvent(tokenData, authenticatedSubjectIdentifier, requestType, serviceProvider);

    }

    @Override
    public void onPreTokenIssue(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPostTokenIssue(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext, AccessTokenDO accessTokenDO, OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, OAuthTokenReqMessageContext oAuthTokenReqMessageContext, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO, OAuthTokenReqMessageContext oAuthTokenReqMessageContext, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPreTokenRevocationByClient(OAuthRevocationRequestDTO oAuthRevocationRequestDTO, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPostTokenRevocationByClient(OAuthRevocationRequestDTO oAuthRevocationRequestDTO, OAuthRevocationResponseDTO oAuthRevocationResponseDTO, AccessTokenDO accessTokenDO, RefreshTokenValidationDataDO refreshTokenValidationDataDO, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPreTokenRevocationByResourceOwner(org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO oAuthRevocationRequestDTO, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPostTokenRevocationByResourceOwner(org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO oAuthRevocationRequestDTO, org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO oAuthRevocationResponseDTO, AccessTokenDO accessTokenDO, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPreTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO, OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO, OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO, Map<String, Object> map) throws IdentityOAuth2Exception {

    }

    public void publishTokenIssueEvent(TokenData tokenData,String authenticatedSubjectIdentifier, String requestType,
                                       String serviceProvider) {

        Object[] payloadData = new Object[23];
        payloadData[0] = AuthPublisherConstants.NOT_AVAILABLE;
        payloadData[1] = UUID.randomUUID().toString();
        payloadData[2] = AuthPublisherConstants.STEP_EVENT;
        payloadData[3] = tokenData.isSuccess();
        payloadData[4] = tokenData.getUser();
        payloadData[5] = authenticatedSubjectIdentifier;
        payloadData[6] = tokenData.getUserStoreDomain();
        payloadData[7] = tokenData.getTenantDomain();
        payloadData[8] = AuthPublisherConstants.NOT_AVAILABLE;
        payloadData[9] = AuthPublisherConstants.NOT_AVAILABLE;
        payloadData[10] = requestType;
        payloadData[11] = serviceProvider;
        payloadData[12] = false;
        payloadData[13] = false;
        payloadData[14] = false;
        payloadData[15] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                AuthPublisherConstants.ROLES, getCommaSeparatedUserRoles(tokenData.getUserStoreDomain() + "/" + tokenData
                .getUser(), tokenData.getTenantDomain()));
        payloadData[16] = "1";
        payloadData[17] = "LOCAL";
        payloadData[18] = false;
        payloadData[19] = AuthPublisherConstants.NOT_AVAILABLE;
        payloadData[20] = true;
        payloadData[21] = "LOCAL";
        payloadData[22] = System.currentTimeMillis();

        String[] publishingDomains = (String[]) tokenData.getParameter(OAuthDataPublisherConstants.TENANT_ID);
        if (publishingDomains != null && publishingDomains.length > 0) {
            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = OAuthDataPublisherUtils.getMetaDataArray(publishingDomain);

                    Event event = new Event(TOKEN_ISSUE_EVENT_STREAM_NAME, System.currentTimeMillis(), metadataArray, null, payloadData);
                    CustomOAuthDataPublisherServiceHolder.getInstance().getPublisherService().publish(event);

                    if (LOG.isDebugEnabled() && event != null) {
                        LOG.debug("Sending out event : " + event.toString());
                    }
                }
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    /**
     * Returns the 'username' param in the password grant request.
     *
     * @param tokReqMsgCtx
     * @return Full qualified username
     */
    private String getResourceOwnerUsername(OAuthTokenReqMessageContext tokReqMsgCtx) {
        return tokReqMsgCtx.getOauth2AccessTokenReqDTO().getResourceOwnerUsername();
    }

    private String getRequestType(OAuthTokenReqMessageContext tokReqMsgCtx) {
        boolean isOpenIdConnect = OAuth2Util.isOIDCAuthzRequest(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        return isOpenIdConnect ? FrameworkConstants.OIDC : FrameworkConstants.OAUTH2;

    }

    private String getAuthenticatedSubjectIdentifier(OAuthTokenReqMessageContext tokReqMsgCtx) {
        return tokReqMsgCtx.getAuthorizedUser().getAuthenticatedSubjectIdentifier();
    }

    private boolean isTokenRequestSuccessful(OAuthTokenReqMessageContext tokReqMsgCtx) {
        // If password grant request was successful we will have a valid authorized user set in the token context.
        return tokReqMsgCtx.getAuthorizedUser() != null;
    }

    /**
     * Checks whether request is from password grant.
     *
     * @param tokenReqDTO Token request DTO.
     * @return True if this request is from password grant.
     */
    private boolean isPasswordGrant(OAuth2AccessTokenReqDTO tokenReqDTO) {
        return PASSWORD_GRANT.equals(tokenReqDTO.getGrantType());
    }

    private String getCommaSeparatedUserRoles(String userName, String tenantDomain) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Retrieving roles for user " + userName + ", tenant domain " + tenantDomain);
        }
        if (tenantDomain == null || userName == null) {
            return StringUtils.EMPTY;
        }

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();

        UserStoreManager userstore = null;

        try {
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            if (userRealm != null) {
                userstore = (UserStoreManager) userRealm.getUserStoreManager();
                if (userstore.isExistingUser(userName)) {
                    String[] newRoles = userstore.getRoleListOfUser(userName);
                    StringBuilder sb = new StringBuilder();
                    List<String> externalRoles = AuthnDataPublisherUtils.filterRoles(newRoles);
                    for (String role : externalRoles) {
                        sb.append(",").append(role);
                    }
                    if (sb.length() > 0) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Returning roles, " + sb.substring(1));
                        }
                        return sb.substring(1); //remove the first comma
                    }

                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No realm found. for tenant domain : " + tenantDomain + ". Hence no roles added");
                }
            }
        } catch (UserStoreException e) {
            LOG.error("Error when getting user store for " + userName + "@" + tenantDomain, e);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("No roles found. Returning empty string");
        }
        return StringUtils.EMPTY;
    }

//    public static String getClientIpAddress(HttpServletRequest request) {
//        String[] arr$ = IdentityConstants.HEADERS_WITH_IP;
//        int len$ = arr$.length;
//
//        for(int i$ = 0; i$ < len$; ++i$) {
//            String header = arr$[i$];
//            String ip = request.getHeader(header);
//            if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
//                return getFirstIP(ip);
//            }
//        }
//
//        return request.getRemoteAddr();
//    }
//
//
//    public static String getFirstIP(String commaSeparatedIPs) {
//        return StringUtils.isNotEmpty(commaSeparatedIPs) && commaSeparatedIPs.contains(",") ? commaSeparatedIPs.split(",")[0] : commaSeparatedIPs;
//    }

}
