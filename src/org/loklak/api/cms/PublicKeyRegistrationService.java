/**
 *  PublicKeyRegistrationService
 *  Copyright 29.06.2015 by Robert Mader, @treba13
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
 * This service allows users to register a public key for login
 * Users can also be granted the right to register keys for individual other users or whole user roles
 */
public class PublicKeyRegistrationService extends AbstractAPIHandler implements APIHandler {

	private static final long serialVersionUID = 8578478303032749879L;
	private static final long defaultAccessTokenExpireTime = 7 * 24 * 60 * 60;

	@Override
	public BaseUserRole getMinimalBaseUserRole() {
		return BaseUserRole.ANONYMOUS;
	}

	@Override
	public JSONObject getDefaultPermissions(BaseUserRole baseUserRole) {
		JSONObject result = new JSONObject();

		switch(baseUserRole){
			case ADMIN:
				result.put("self", true);
				result.put("users", new JSONObject());
				JSONObject userRoles = new JSONObject();
				for(String userRole : DAO.userRoles.getUserRoles().keySet()){
					userRoles.put(userRole, true);
				}
				result.put("userRoles", userRoles);
				break;
			case PRIVILEGED:
			case USER:
				result.put("self", true);
				result.put("users", new JSONObject());
				result.put("userRoles", new JSONObject());
				break;
			case ANONYMOUS:
			default:
				result.put("self", false);
				result.put("users", new JSONObject());
				result.put("userRoles", new JSONObject());
		}

		return result;
	}

	public String getAPIPath() {
		return "/api/registerpublickey.json";
	}

	@Override
	public JSONObject serviceImpl(Query post, HttpServletResponse response, Authorization authorization, final JSONObjectWithDefault permissions)
			throws APIException {

		if(post.get("public_key",null) == null) throw new APIException(400, "No public_key specified");

		String id;
		if(post.get("id", null) != null) id = post.get("id", null);
		else id = authorization.getIdentity().getName();

		// check if we are allowed register a key
		if(!id.equals(authorization.getIdentity().getName())){ // if we don't want to register the key for the current user

			// create Authentication to check if the user id is a registered user
			ClientCredential credential = new ClientCredential(ClientCredential.Type.passwd_login, id);
			Authentication authentication = new Authentication(credential, DAO.authentication);

			if (authentication.getIdentity() == null) { // check if identity is valid
				authentication.delete();
				throw new APIException(400, "Bad request"); // do not leak if user exists or not
			}

			// check if the current user is allowed to create a key for the user in question
			boolean allowed = false;
			// check if the user in question is in 'users'
			if(permissions.getJSONObject("users", null).has(id) && permissions.getJSONObjectWithDefault("users", null).getBoolean(id, false)){
				allowed = true;
			}
			else { // check if the user role of the user in question is in 'userRoles'
				Authorization auth = new Authorization(authentication.getIdentity(), DAO.authorization, DAO.userRoles);
				for(String key : permissions.getJSONObject("userRoles").keySet()){
					if(key.equals(auth.getUserRole().getName()) && permissions.getJSONObject("userRoles").getBoolean(key)){
						allowed = true;
					}
				}
			}
			if(!allowed) throw new APIException(400, "Bad request"); // do not leak if user exists or not
		}
		else{ // if we want to register a key for this user, bad are not allowed to (for example anonymous users)
			if(!permissions.getBoolean("self", false)) throw new APIException(403, "You are not allowed to register a public key");
		}

		// TODO: the actual key registration

		JSONObject result = new JSONObject();

		return result;
	}
}
