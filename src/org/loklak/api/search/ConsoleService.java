/**
 *  TableService
 *  Copyright 13.06.2015 by Michael Peter Christen, @0rb1t3r
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

package org.loklak.api.search;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.elasticsearch.search.sort.SortOrder;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.loklak.data.DAO;
import org.loklak.geo.GeoMark;
import org.loklak.http.ClientConnection;
import org.loklak.objects.AccountEntry;
import org.loklak.objects.QueryEntry;
import org.loklak.objects.ResultList;
import org.loklak.objects.Timeline;
import org.loklak.objects.UserEntry;
import org.loklak.server.APIException;
import org.loklak.server.APIHandler;
import org.loklak.server.BaseUserRole;
import org.loklak.server.AbstractAPIHandler;
import org.loklak.server.Authorization;
import org.loklak.server.Query;
import org.loklak.susi.SusiThought;

import com.google.common.util.concurrent.AtomicDouble;
import org.loklak.tools.storage.JSONObjectWithDefault;

/* examples:
 * http://localhost:9000/api/console.json?q=SELECT%20text,%20screen_name,%20user.name%20AS%20user%20FROM%20messages%20WHERE%20query=%271%27;
 * http://localhost:9000/api/console.json?q=SELECT%20*%20FROM%20messages%20WHERE%20id=%27742384468560912386%27;
 * http://localhost:9000/api/console.json?q=SELECT%20link,screen_name%20FROM%20messages%20WHERE%20id=%27742384468560912386%27;
 * http://localhost:9000/api/console.json?q=SELECT%20COUNT(*)%20AS%20count,%20screen_name%20AS%20twitterer%20FROM%20messages%20WHERE%20query=%27loklak%27%20GROUP%20BY%20screen_name;
 * http://localhost:9000/api/console.json?q=SELECT%20PERCENT(count)%20AS%20percent,%20screen_name%20FROM%20(SELECT%20COUNT(*)%20AS%20count,%20screen_name%20FROM%20messages%20WHERE%20query=%27loklak%27%20GROUP%20BY%20screen_name)%20WHERE%20screen_name%20IN%20(%27leonmakk%27,%27Daminisatya%27,%27sudheesh001%27,%27shiven_mian%27);
 * http://localhost:9000/api/console.json?q=SELECT%20query,%20query_count%20AS%20count%20FROM%20queries%20WHERE%20query=%27auto%27;
 * http://localhost:9000/api/console.json?q=SELECT%20*%20FROM%20users%20WHERE%20screen_name=%270rb1t3r%27;
 * http://localhost:9000/api/console.json?q=SELECT%20place[0]%20AS%20place,%20population,%20location[0]%20AS%20lon,%20location[1]%20AS%20lat%20FROM%20locations%20WHERE%20location=%27Berlin%27;
 * http://localhost:9000/api/console.json?q=SELECT%20*%20FROM%20locations%20WHERE%20location=%2753.1,13.1%27;
 * http://localhost:9000/api/console.json?q=SELECT%20description%20FROM%20wikidata%20WHERE%20query=%27football%27;
 * http://localhost:9000/api/console.json?q=SELECT%20*%20FROM%20meetup%20WHERE%20url=%27http://www.meetup.com/?q=Women-Who-Code-Delhi%27;
 * http://localhost:9000/api/console.json?q=SELECT%20*%20FROM%20rss%20WHERE%20url=%27https://www.reddit.com/search.rss?q=loklak%27;
 * http://localhost:9000/api/console.json?q=SELECT%20*%20FROM%20eventbrite%20WHERE%20url=%27https://www.eventbrite.fr/e/billets-europeade-2016-concert-de-musique-vocale-25592599153?aff=es2%27;
 */
public class ConsoleService extends AbstractAPIHandler implements APIHandler {
   
    private static final long serialVersionUID = 8578478303032749879L;

    @Override
    public BaseUserRole getMinimalBaseUserRole() { return BaseUserRole.ANONYMOUS; }

    @Override
    public JSONObject getDefaultPermissions(BaseUserRole baseUserRole) {
        return null;
    }

    public String getAPIPath() {
        return "/api/console.json";
    }

    private static LinkedHashMap<String, String> parseCommaList(String cl) {
        LinkedHashMap<String, String> columns;
        String[] column_list = cl.trim().split(",");
        if (column_list.length == 1 && column_list[0].equals("*")) {
            columns = null;
        } else {
            columns = new LinkedHashMap<>();
            for (String column: column_list) {
                String c = column.trim();
                int p = c.indexOf(" AS ");
                if (p < 0) {
                    c = trimQuotes(c);
                    columns.put(c, c);
                } else {
                    columns.put(trimQuotes(c.substring(0,  p).trim()), trimQuotes(c.substring(p + 4).trim()));
                }
            }
        }
        return columns;
    }
    private static String trimQuotes(String s) {
        if (s.length() == 0) return s;
        if (s.charAt(0) == '\'' || s.charAt(0) == '\"') s = s.substring(1);
        if (s.charAt(s.length() - 1) == '\'' || s.charAt(s.length() - 1) == '\"') s = s.substring(0, s.length() - 1);
        return s;
    }
    
    private static class Columns {
        private LinkedHashMap<String, String> columns;
        
        public Columns(String columnString) {
            this.columns = parseCommaList(columnString);
        }
        
        public JSONObject extractRow(JSONObject message) {
            if (this.columns == null) return message;
            JSONObject json = new JSONObject(true);
            for (Map.Entry<String, String> c: columns.entrySet()) {
                String key = c.getKey();
                int p = key.indexOf('.');
                if (p > 0) {
                    // sub-element
                    String k0 = key.substring(0,  p);
                    String k1 = key.substring(p + 1);
                    if (message.has(k0)) {
                        if (k1.equals("length") || k1.equals("size()")) {
                            Object a = message.get(k0);
                            if (a instanceof String[]) {
                                json.put(c.getValue(),((String[]) a).length);
                            } else if (a instanceof JSONArray) {
                                json.put(c.getValue(),((JSONArray) a).length());
                            }
                        } else {
                            JSONObject o = message.getJSONObject(k0);
                            if (o.has(k1)) json.put(c.getValue(), o.get(k1));
                        }
                    }
                } else if ((p = key.indexOf('[')) > 0) {
                    // array
                    int q = key.indexOf("]", p);
                    if (q > 0) {
                        String k0 = key.substring(0,  p);
                        int i = Integer.parseInt(key.substring(p + 1, q));
                        if (message.has(k0)) {
                            JSONArray a = message.getJSONArray(k0);
                            if (i < a.length()) json.put(c.getValue(), a.get(i));
                        }
                    }
                } else {
                    // flat
                    if (message.has(key)) json.put(c.getValue(), message.get(key));
                }
            }
            return json;
        }
        
        public JSONArray extractTable(JSONArray rows) {
            JSONArray a = new JSONArray();
            if (this.columns != null && this.columns.size() == 1) {
                // test if this has an aggregation key: AVG, COUNT, MAX, MIN, SUM
                final String aggregator = this.columns.keySet().iterator().next();
                final String aggregator_as = this.columns.get(aggregator);
                if (aggregator.startsWith("COUNT(") && aggregator.endsWith(")")) { // TODO: there should be a special pattern for this to make it more efficient
                    return a.put(new JSONObject().put(aggregator_as, rows.length()));
                }
                if (aggregator.startsWith("MAX(") && aggregator.endsWith(")")) {
                    final AtomicDouble max = new AtomicDouble(Double.MIN_VALUE); String c = aggregator.substring(4, aggregator.length() - 1);
                    rows.forEach(json -> max.set(Math.max(max.get(), ((JSONObject) json).getDouble(c))));
                    return a.put(new JSONObject().put(aggregator_as, max.get()));
                }
                if (aggregator.startsWith("MIN(") && aggregator.endsWith(")")) {
                    final AtomicDouble min = new AtomicDouble(Double.MAX_VALUE); String c = aggregator.substring(4, aggregator.length() - 1);
                    rows.forEach(json -> min.set(Math.min(min.get(), ((JSONObject) json).getDouble(c))));
                    return a.put(new JSONObject().put(aggregator_as, min.get()));
                }
                if (aggregator.startsWith("SUM(") && aggregator.endsWith(")")) {
                    final AtomicDouble sum = new AtomicDouble(0.0d); String c = aggregator.substring(4, aggregator.length() - 1);
                    rows.forEach(json -> sum.addAndGet(((JSONObject) json).getDouble(c)));
                    return a.put(new JSONObject().put(aggregator_as, sum.get()));
                }
                if (aggregator.startsWith("AVG(") && aggregator.endsWith(")")) {
                    final AtomicDouble sum = new AtomicDouble(0.0d); String c = aggregator.substring(4, aggregator.length() - 1);
                    rows.forEach(json -> sum.addAndGet(((JSONObject) json).getDouble(c)));
                    return a.put(new JSONObject().put(aggregator_as, sum.get() / rows.length()));
                }
            }
            if (this.columns != null && this.columns.size() == 2) {
                Iterator<String> ci = this.columns.keySet().iterator();
                String aggregator = ci.next(); String column = ci.next();
                if (column.indexOf('(') >= 0) {String s = aggregator; aggregator = column; column = s;}
                final String aggregator_as = this.columns.get(aggregator);
                final String column_as = this.columns.get(column);
                final String column_final = column;
                if (aggregator.startsWith("PERCENT(") && aggregator.endsWith(")")) {
                    final AtomicDouble sum = new AtomicDouble(0.0d); String c = aggregator.substring(8, aggregator.length() - 1);
                    rows.forEach(json -> sum.addAndGet(((JSONObject) json).getDouble(c)));
                    rows.forEach(json -> a.put(new JSONObject()
                            .put(aggregator_as, 100.0d * ((JSONObject) json).getDouble(c) / sum.get())
                            .put(column_as, ((JSONObject) json).get(column_final))));
                    return a;
                }
            }
            for (Object json: rows) a.put(this.extractRow((JSONObject) json));
            return a;
        }
        public String toString() {
            return this.columns == null ? "NULL" : this.columns.toString();
        }
    }
    
    private final static LinkedHashMap<Pattern, Function<Matcher, SusiThought>> pattern = new LinkedHashMap<>();
    static {
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?\\(\\h??SELECT\\h+?(.*?)\\h??\\)\\h+?WHERE\\h+?(.*?)\\h?+IN\\h?+\\((.*?)\\)\\h??;"), matcher -> {
            Columns columns = new Columns(matcher.group(1));
            String subquery = matcher.group(2).trim();
            if (!subquery.endsWith(";")) subquery = subquery + ";";
            String filter_name = matcher.group(3);
            Set<String> filter_set = parseCommaList(matcher.group(4)).keySet();
            JSONArray a0 = console("SELECT " + subquery).getJSONArray("data");
            JSONArray a1 = new JSONArray();
            a0.forEach(o -> {
                JSONObject j = (JSONObject) o;
                if (j.has(filter_name) && filter_set.contains(j.getString(filter_name))) a1.put(j);
            });
            return new SusiThought()
                    .setOffset(0).setHits(a0.length())
                    .setData(columns.extractTable(a1));
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?messages\\h+?WHERE\\h+?id\\h??=\\h??'(.*?)'\\h??;"), matcher -> {
            Columns columns = new Columns(matcher.group(1));
            JSONObject message = DAO.messages.readJSON(matcher.group(2));
            return message == null ? null : new SusiThought()
                    .setOffset(0).setHits(1)
                    .setData((new JSONArray()).put(columns.extractRow(message)));
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?messages\\h+?WHERE\\h+?query\\h??=\\h??'(.*?)'\\h?+GROUP\\h?+BY\\h?+(.*?)\\h??;"), matcher -> {
            Columns columns = new Columns(matcher.group(1));
            String group = matcher.group(3);
            DAO.SearchLocalMessages messages = new DAO.SearchLocalMessages(matcher.group(2), Timeline.Order.CREATED_AT, 0, 0, 100, group);
            JSONArray array = new JSONArray();
            JSONObject aggregation = messages.getAggregations().getJSONObject(group);
            
            for (String key: aggregation.keySet()) array.put(new JSONObject(true).put(group, key).put("COUNT(*)", aggregation.get(key)));
            SusiThought json = messages.timeline.toSusi(true);
            return json.setData(columns.extractTable(array));
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?messages\\h+?WHERE\\h+?query\\h??=\\h??'(.*?)'\\h??;"), matcher -> {
            Columns columns = new Columns(matcher.group(1));
            DAO.SearchLocalMessages messages = new DAO.SearchLocalMessages(matcher.group(2), Timeline.Order.CREATED_AT, 0, 100, 0);
            SusiThought json = messages.timeline.toSusi(true);
            return json.setData(columns.extractTable(json.getJSONArray("data")));
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?queries\\h+?WHERE\\h+?query\\h??=\\h??'(.*?)'\\h??;"), matcher -> {
            Columns columns = new Columns(matcher.group(1));
            ResultList<QueryEntry> queries = DAO.SearchLocalQueries(matcher.group(2), 100, "retrieval_next", "date", SortOrder.ASC, null, new Date(), "retrieval_next");
            SusiThought json = queries.toSusi();
            json.setQuery(matcher.group(2));
            return json.setData(columns.extractTable(json.getJSONArray("data")));
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?users\\h+?WHERE\\h+?screen_name\\h??=\\h??'(.*?)'\\h??;"), matcher -> {
            Columns columns = new Columns(matcher.group(1));
            UserEntry user_entry = DAO.searchLocalUserByScreenName(matcher.group(2));
            SusiThought json = new SusiThought();
            json.setQuery(matcher.group(2));
            if (user_entry == null) {
                json.setHits(0).setData(new JSONArray());
            } else {
                json.setHits(1).setData(new JSONArray().put(user_entry.toJSON()));
            }
            return json.setData(columns.extractTable(json.getJSONArray("data")));
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?accounts\\h+?WHERE\\h+?screen_name\\h??=\\h??'(.*?)'\\h??;"), matcher -> {
            Columns columns = new Columns(matcher.group(1));
            AccountEntry account_entry = DAO.searchLocalAccount(matcher.group(2));
            SusiThought json = new SusiThought();
            json.setQuery(matcher.group(2));
            if (account_entry == null) {
                json.setHits(0).setData(new JSONArray());
            } else {
                json.setHits(1).setData(new JSONArray().put(account_entry.toJSON()));
            }
            return json.setData(columns.extractTable(json.getJSONArray("data")));
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?locations\\h+?WHERE\\h+?location\\h??=\\h??'(.*?)'\\h??;"), matcher -> {
            Columns columns = new Columns(matcher.group(1));
            GeoMark loc = DAO.geoNames.analyse(matcher.group(2), null, 5, Long.toString(System.currentTimeMillis()));
            SusiThought json = new SusiThought();
            json.setQuery(matcher.group(2));
            if (loc == null) {
                json.setHits(0).setData(new JSONArray());
            } else {
                json.setHits(1).setData(new JSONArray().put(loc.toJSON(false)));
            }
            return json.setData(columns.extractTable(json.getJSONArray("data")));
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?wikidata\\h+?WHERE\\h+?query\\h??=\\h??'(.*?)'\\h??;"), matcher -> {
            JSONObject wikidata;
            try {
                ClientConnection cc = new ClientConnection("https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json&language=en&search=" + URLEncoder.encode(matcher.group(2), "UTF-8"));
                wikidata = new JSONObject(new JSONTokener(cc.inputStream));
                cc.close();
            } catch (IOException | JSONException e) {wikidata = new JSONObject();}
            SusiThought json = new SusiThought();
            json.setQuery(matcher.group(2));
            Columns columns = new Columns(matcher.group(1));
            json.setData(columns.extractTable(wikidata.getJSONArray("search")));
            json.setHits(json.getCount());
            return json;
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?meetup\\h+?WHERE\\h+?url\\h??=\\h??'(.*?)'\\h??;"), matcher -> {
            SusiThought json = MeetupsCrawlerService.crawlMeetups(matcher.group(2));
            Columns columns = new Columns(matcher.group(1));
            json.setData(columns.extractTable(json.getData()));
            return json;
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?rss\\h+?WHERE\\h+?url\\h??=\\h??'(.*?)'\\h??;"), matcher -> {
            SusiThought json = RSSReaderService.readRSS(matcher.group(2));
            Columns columns = new Columns(matcher.group(1));
            json.setData(columns.extractTable(json.getData()));
            return json;
        });
        pattern.put(Pattern.compile("SELECT\\h+?(.*?)\\h+?FROM\\h+?eventbrite\\h+?WHERE\\h+?url\\h??=\\h??'(.*?)'\\h??;"), matcher -> {
            SusiThought json = EventBriteCrawlerService.crawlEventBrite(matcher.group(2));
            Columns columns = new Columns(matcher.group(1));
            json.setData(columns.extractTable(json.getData()));
            return json;
        });
        
    }

    public static SusiThought console(String q) {
        if (q == null) return new SusiThought();
        SusiThought json = null;
        q = q.trim();
        find_matcher: for (Map.Entry<Pattern, Function<Matcher, SusiThought>> pe: pattern.entrySet()) {
            Pattern p = pe.getKey();
            Matcher m = p.matcher(q);
            if (m.find()) {
                json = pe.getValue().apply(m);
                if (json != null) break find_matcher;
            }
        }
        
        // return json
        if (json == null) json = new SusiThought();
        return json;
    }
    
    @Override
    public JSONObject serviceImpl(Query post, Authorization rights, final JSONObjectWithDefault permissions) throws APIException {

        // parameters
        String q = post.get("q", "");
        //int timezoneOffset = post.get("timezoneOffset", 0);
        
        return console(q);
    }
    
}
