# Custom Password Grant Handler for  [WSO2 Identity Server](https://wso2.com/identity-and-access-management/) 5.9.0

 * This custom password grant handler overrides the default password grant handler and append the userstore domain to username.
 * The userstore domain is picked within scopes.
 * If a scope starts with "US_" it's considered as the userstore domain.

### Steps to deploy
- Build the component by running "mvn clean install".
- Copy `custom-password-grant-1.0.0.jar` file which can be found in target directory into `<IS_HOME>/repository/components/lib' directory.
- Open `repository/conf/deployment.toml` file and add the following config.
```dtd
[oauth.grant_type.password]
grant_handler = "org.wso2.identity.custom.grant.password.CustomPasswordGrantHandler"
```
- Restart the Identity Server.