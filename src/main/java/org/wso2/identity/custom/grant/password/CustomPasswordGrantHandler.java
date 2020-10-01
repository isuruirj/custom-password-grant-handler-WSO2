package org.wso2.identity.custom.grant.password;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;

/**
 * Modified version of password grant type to append the userstore domain to username.
 * The userstore domain is picked within scopes.
 * If a scope starts with "US_" it's considered as the userstore domain.
 */
public class CustomPasswordGrantHandler extends PasswordGrantHandler {

    private static Log log = LogFactory.getLog(CustomPasswordGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        String userFromRequest = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getResourceOwnerUsername();
        String [] scopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();

        for(String scope : scopes) {
            if (scope.startsWith("US_")) {

                String userstoreDomain = scope.substring(3);
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().setResourceOwnerUsername(userstoreDomain + "/" + userFromRequest);

                if (log.isDebugEnabled()) {
                    log.debug("Username: " + userFromRequest + ", User store domain: " + userstoreDomain);
                }
                break;
            }
        }

        return super.validateGrant(tokReqMsgCtx);
    }

}
