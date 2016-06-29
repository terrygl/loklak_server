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

		return null;
	}
}
