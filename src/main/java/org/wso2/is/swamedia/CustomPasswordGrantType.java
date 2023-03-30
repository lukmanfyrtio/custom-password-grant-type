package org.wso2.is.swamedia;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

public class CustomPasswordGrantType extends PasswordGrantHandler {

	private static Log log = LogFactory.getLog(CustomPasswordGrantType.class);
	 public static final String USERNAME_GRANT_PARAM = "username";
	 public static final String PASSWORD_GRANT_PARAM = "password";

	@Override
	public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
		log.info("call validateGrant from CustomPasswordGrantType class");

		AbstractAuthorizationGrantHandler abstractAuthorizationGrantHandler=new AbstractAuthorizationGrantHandler() {
		};
		if (!abstractAuthorizationGrantHandler.validateGrant(tokReqMsgCtx)) {
			return false;
		}
		
        // extract request parameters
        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        log.info("request parameter " + parameters);
        String username = null;
        String password = null;
        // find out mobile number
        log.info("find out username & password");
        for(RequestParameter parameter : parameters){
            if(USERNAME_GRANT_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                   username = parameter.getValue()[0];
                }
            }
            if(PASSWORD_GRANT_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                	password = parameter.getValue()[0];
                }
            }
        }
        log.info("username : "+username);
        log.info("password : "+password);
		OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
		String userTenantDomain = MultitenantUtils.getTenantDomain(username);
		String clientId = oAuth2AccessTokenReqDTO.getClientId();
		String tenantDomain = oAuth2AccessTokenReqDTO.getTenantDomain();
		
		log.info("userTenantDomain : "+userTenantDomain);
		log.info("clientId : "+clientId);
		log.info("tenantDomain : "+tenantDomain);
		ServiceProvider serviceProvider = null;
		try {
			log.info("getting data oauth2 service provider ------> ");
			serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService()
					.getServiceProviderByClientId(clientId, "oauth2", tenantDomain);
			log.info("appName : " + serviceProvider.getApplicationName());
		} catch (IdentityApplicationManagementException e) {
			throw new IdentityOAuth2Exception(
					"Error occurred while retrieving OAuth2 application data for client id " + clientId, e);
		}
		if (!serviceProvider.isSaasApp() && !userTenantDomain.equals(tenantDomain)) {
			if (log.isDebugEnabled()) {
				log.debug("Non-SaaS service provider tenant domain is not same as user tenant domain; " + tenantDomain
						+ " != " + userTenantDomain);
			}
			return false;

		}
		String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);
		log.info("tenantAwareUserName : " + tenantAwareUserName);
		username = tenantAwareUserName + "@" + userTenantDomain;
		log.info("username : " + username);
		int tenantId = MultitenantConstants.INVALID_TENANT_ID;

		try {
			tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
			log.info("tenantId : " + tenantId);
			log.info("tenantId from carbonContext: " + CarbonContext.getThreadLocalCarbonContext().getTenantId());
		} catch (IdentityRuntimeException e) {
			log.error("Token request with Password Grant Type for an invalid tenant : "
					+ MultitenantUtils.getTenantDomain(username));
			return false;
		}

//		RealmService realmService = OAuthComponentServiceHolder.getRealmService();
		UserStoreManager userStoreManager = null;
		boolean authStatus;
		try {
			userStoreManager = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager();
			authStatus = userStoreManager.authenticate(tenantAwareUserName,
					password);

			if (log.isDebugEnabled()) {
				log.debug("Token request with Password Grant Type received. " + "Username : " + username + "Scope : "
						+ OAuth2Util.buildScopeString(oAuth2AccessTokenReqDTO.getScope()) + ", Authentication State : "
						+ authStatus);
			}

		} catch (UserStoreException e) {
			throw new IdentityOAuth2Exception(e.getMessage(), e);
		}

		if (authStatus) {
			if (username.indexOf(CarbonConstants.DOMAIN_SEPARATOR) < 0
					&& UserCoreUtil.getDomainFromThreadLocal() != null
					&& !"".equals(UserCoreUtil.getDomainFromThreadLocal())) {
				username = UserCoreUtil.getDomainFromThreadLocal() + CarbonConstants.DOMAIN_SEPARATOR + username;
			}
			tokReqMsgCtx.setAuthorizedUser(OAuth2Util.getUserFromUserName(username));
			tokReqMsgCtx.setScope(oAuth2AccessTokenReqDTO.getScope());
		} else {
			throw new IdentityOAuth2Exception("Authentication failed for " + username);
		}
		return authStatus;
	}
}
