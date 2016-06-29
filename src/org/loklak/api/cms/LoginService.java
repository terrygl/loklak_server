/**
 *  LoginServlet
 *  Copyright 27.05.2015 by Robert Mader, @treba13
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *  
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *  
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program in the file lgpl21.txt
 *  If not, see <http://www.gnu.org/licenses/>.
 */

package org.loklak.api.cms;

import org.eclipse.jetty.util.log.Log;
import org.json.JSONObject;
import org.loklak.data.DAO;
import org.loklak.server.*;
import org.loklak.tools.storage.JSONObjectWithDefault;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.net.URLDecoder;
import java.time.Instant;
import java.util.TreeMap;

/**
 * This login allows users to login or to check if they are logged in already.
 * For login, there are three options: session, cookie (both stateful, for browsers) and access-token (stateless, for api access)
 * It requires the following parameters: login (the login id, usually an email, password and type (one of the above)
 * To check if the user is logged it, set the parameter 'checkLogin' to true
 */
public class LoginService extends AbstractAPIHandler implements APIHandler {

	private static final long serialVersionUID = 8578478303032749879L;
	private static final long defaultAccessTokenExpireTime = 7 * 24 * 60 * 60;

	@Override
	public BaseUserRole getMinimalBaseUserRole() {
		return BaseUserRole.ANONYMOUS;
	}

	@Override
	public JSONObject getDefaultPermissions(BaseUserRole baseUserRole) {
		JSONObject result = new JSONObject();
		result.put("maxInvalidLogins", 10);
		result.put("blockTimeSeconds", 20);
		return result;
	}

	public String getAPIPath() {
		return "/api/login.json";
	}

	@Override
	public JSONObject serviceImpl(Query post, HttpServletResponse response, Authorization authorization, final JSONObjectWithDefault permissions)
			throws APIException {

		// login check for app
		if(post.get("checkLogin", false)) {
			JSONObject result = new JSONObject();
			if (authorization.getIdentity().isEmail()) {
				result.put("loggedIn", true);
				result.put("message", "You are logged in as " + authorization.getIdentity().getName());
			}
			else{
				result.put("loggedIn", false);
				result.put("message", "Not logged in");
			}
			return result;
		}

		// check for login information
		if(post.get("logout", false)){	// logout if requested

			// invalidate session
			post.getRequest().getSession().invalidate();

			// delete cookie if set
			deleteLoginCookie(response);

			JSONObject result = new JSONObject();
			result.put("message", "Logout successful");
			return result;
		}


			// check if all required parameters are set
		if (post.get("login", null) == null || post.get("password", null) == null || post.get("type", null ) == null) {
			throw new APIException(400, "Login requires the parameters 'login', 'password' and 'type'");
		}


		// check if too many invalid login attempts were made already
		TreeMap<Long, String> invalidLogins = authorization.getAccounting().getRequests(this.getClass().getCanonicalName());
		Long lastKey = invalidLogins.floorKey(System.currentTimeMillis() + 1000);
		if(invalidLogins.size() > permissions.getInt("maxInvalidLogins", 10)
				&& lastKey > System.currentTimeMillis() - permissions.getInt("blockTimeSeconds", 120) * 1000){
			throw new APIException(403, "Too many invalid login attempts. Try again in "
					+ (permissions.getInt("blockTimeSeconds", 120) * 1000 - System.currentTimeMillis() + lastKey) / 1000
					+ " seconds");
		}


		// fetch parameters
		String login;
		String password;
		String type;
		try {
			login = URLDecoder.decode(post.get("login", null), "UTF-8");
			password = URLDecoder.decode(post.get("password", null), "UTF-8");
			type = URLDecoder.decode(post.get("type", null), "UTF-8");
		} catch (Throwable e) {
			throw new APIException(500, "Server error");
		}

		// create Authentication
		ClientCredential credential = new ClientCredential(ClientCredential.Type.passwd_login, login);
		Authentication authentication = new Authentication(credential, DAO.authentication);

		if (authentication.getIdentity() == null) { // check if identity is valid
			authentication.delete();
			Log.getLog().info("Invalid login try for unknown user: " + credential.getName() + " via passwd from host: " + post.getClientHost());
			throw new APIException(422, "Invalid credentials");
		}

		if (!authentication.getBoolean("activated", false)) { // check if identity is valid
			Log.getLog().info("Invalid login try for user: " + credential.getName() + " from host: " + post.getClientHost() + " : user not activated yet");
			throw new APIException(422, "User not yet activated");
		}

		// check if the password is valid
		String passwordHash;
		String salt;
		try {
			passwordHash = authentication.getString("passwordHash");
			salt = authentication.getString("salt");
		} catch (Throwable e) {
			Log.getLog().info("Invalid login try for user: " + credential.getName() + " from host: " + post.getClientHost() + " : password or salt missing in database");
			throw new APIException(422, "Invalid credentials");
		}

		if (!passwordHash.equals(getHash(password, salt))) {

			// save invalid login in accounting object
			authorization.getAccounting().addRequest(this.getClass().getCanonicalName(), "invalid login");

			Log.getLog().info("Invalid login try for user: " + credential.getName() + " via passwd from host: " + post.getClientHost());
			throw new APIException(422, "Invalid credentials");
		}

		ClientIdentity identity = authentication.getIdentity();
		JSONObject result = new JSONObject();

		switch (type) {
			case "session": // create a browser session
				post.getRequest().getSession().setAttribute("identity", identity);
				break;
			case "cookie": // set a long living cookie
				// create random string as token
				String loginToken = createRandomString(30);

				// create cookie
				Cookie loginCookie = new Cookie("login", loginToken);
				loginCookie.setPath("/");
				loginCookie.setMaxAge(defaultCookieTime.intValue());

				// write cookie to database
				ClientCredential cookieCredential = new ClientCredential(ClientCredential.Type.cookie, loginToken);
				JSONObject user_obj = new JSONObject();
				user_obj.put("id", identity.toString());
				user_obj.put("expires_on", Instant.now().getEpochSecond() + defaultCookieTime);
				DAO.authentication.put(cookieCredential.toString(), user_obj, cookieCredential.isPersistent());

				response.addCookie(loginCookie);
				break;
			case "access-token": // create and display an access token

				// create token
				String token = createRandomString(30);
				ClientCredential accessToken = new ClientCredential(ClientCredential.Type.access_token, token);
				Authentication tokenAuthentication = new Authentication(accessToken, DAO.authentication);
				tokenAuthentication.setIdentity(identity);

				long valid_seconds;
				try {
					valid_seconds = post.get("valid_seconds", defaultAccessTokenExpireTime);
				} catch (Throwable e) {
					throw new APIException(400, "Invalid value for 'valid_seconds'");
				}

				if (valid_seconds == -1) { // valid forever
					result.put("valid_seconds", "forever");
				} // -1 means forever, don't add expire time
				else if (valid_seconds == 0 || valid_seconds < -1) { // invalid values
					throw new APIException(400, "Invalid value for 'valid_seconds'");
				} else {
					tokenAuthentication.setExpireTime(valid_seconds);
					result.put("valid_seconds", valid_seconds);
				}
				result.put("access_token", token);

				break;
			default:
				throw new APIException(400, "Invalid type");
		}

		Log.getLog().info("login for user: " + credential.getName() + " via passwd from host: " + post.getClientHost());

		result.put("message", "You are logged in as " + identity.getName());
		return result;
	}
}
