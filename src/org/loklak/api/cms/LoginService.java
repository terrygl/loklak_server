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
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.time.Instant;

public class LoginService extends AbstractAPIHandler implements APIHandler {

	private static final long serialVersionUID = 8578478303032749879L;

	@Override
	public BaseUserRole getMinimalBaseUserRole() {
		return BaseUserRole.ANONYMOUS;
	}

	@Override
	public JSONObject getDefaultPermissions(BaseUserRole baseUserRole) {
		JSONObject result = new JSONObject();
		result.put("maxInvalidLogins", 10);
		return result;
	}

	public String getAPIPath() {
		return "/api/login.json";
	}

	@Override
	public JSONObject serviceImpl(Query post, HttpServletResponse response, Authorization authorization, final JSONObjectWithDefault permissions)
			throws APIException {

		JSONObject result = new JSONObject();

		// if logged in already, return only a message
		if (authorization.getIdentity().getType() != ClientIdentity.Type.host) {
			result.put("loggedIn", true);
			result.put("message", "You are logged in as " + authorization.getIdentity().getName());
			return result;
		}

		if (post.get("login", null) != null && post.get("password", null) != null ){ // check if login parameters are set


			String login = null;
			String password = null;
			try {
				login = URLDecoder.decode(post.get("login" ,null), "UTF-8");
				password = URLDecoder.decode(post.get("password", null), "UTF-8");
			} catch (Throwable e) {
				throw new APIException(500, "Server error");
			}

			ClientCredential credential = new ClientCredential(ClientCredential.Type.passwd_login, login);
			Authentication authentication = new Authentication(credential, DAO.authentication);

			// check if password is valid
			if(authentication.getIdentity() != null){

				if(authentication.has("activated") && authentication.getBoolean("activated")){

					if(authentication.has("passwordHash") && authentication.has("salt")){

						String passwordHash = authentication.getString("passwordHash");
						String salt = authentication.getString("salt");

						if(getHash(password, salt).equals(passwordHash)){

							ClientIdentity identity = authentication.getIdentity();

							// only create a cookie or session if requested (by login page)
							if("true".equals(post.get("request_cookie", null))){

								// create random string as token
								String loginToken = createRandomString(30);

								// create cookie
								Cookie loginCookie = new Cookie("login", loginToken);
								loginCookie.setPath("/");
								loginCookie.setMaxAge(defaultCookieTime.intValue());

								// write cookie to database
								ClientCredential cookieCredential = new ClientCredential(ClientCredential.Type.cookie, loginToken);
								JSONObject user_obj = new JSONObject();
								user_obj.put("id",identity.toString());
								user_obj.put("expires_on", Instant.now().getEpochSecond() + defaultCookieTime);
								DAO.authentication.put(cookieCredential.toString(), user_obj, cookieCredential.isPersistent());

								response.addCookie(loginCookie);
							}
							else if("true".equals(post.get("request_session", null))){
								post.getRequest().getSession().setAttribute("identity",identity);
							}

							Log.getLog().info("login for user: " + credential.getName() + " via passwd from host: " + post.getClientHost());

							result.put("loggedIn", true);
							result.put("message", "You are logged in as " + identity.getName());
							return result;
						}
						// invalid login try, we have to limit this
						permissions.getInt("maxInvalidLogins", 10);

						Log.getLog().info("Invalid login try for user: " + credential.getName() + " via passwd from host: " + post.getClientHost());
						throw new APIException(422, "Invalid credentials");
					}
					Log.getLog().info("Invalid login try for user: " + credential.getName() + " from host: " + post.getClientHost() + " : password or salt missing in database");
					throw new APIException(422, "Invalid credentials");
				}
				Log.getLog().info("Invalid login try for user: " + credential.getName() + " from host: " + post.getClientHost() + " : user not activated yet");
				throw new APIException(422, "User not yet activated");
			}
			else{
				authentication.delete();
				Log.getLog().info("Invalid login try for unknown user: " + credential.getName() + " via passwd from host: " + post.getClientHost());
				throw new APIException(422, "Invalid credentials");
			}
		}

		result.put("loggedIn", false);
		result.put("message", "You are not logged in ");
		return result;
	}
}
