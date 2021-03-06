/**
 *  SusiMemory
 *  Copyright 29.06.2016 by Michael Peter Christen, @0rb1t3r
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

package org.loklak.susi;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.loklak.data.DAO;

public class SusiMind {
    
    private final Map<String,String> synonyms; // a map from a synonym to a canonical expression
    private final Map<String,String> categories; // a map from an expression to an associated category name
    private final Set<String> filler; // a set of words that can be ignored completely
    private final Map<String, Map<Long, SusiRule>> ruletrigger; // a map from a keyword to a list of actions
    private final File initpath, watchpath; // a path where the memory looks for new additions of knowledge with memory files
    private final Map<File, Long> observations; // a mapping of mind memory files to the time when the file was read the last time
    
    public SusiMind(File initpath, File watchpath) {
        // initialize class objects
        this.initpath = initpath;
        this.initpath.mkdirs();
        this.watchpath = watchpath;
        this.watchpath.mkdirs();
        this.synonyms = new ConcurrentHashMap<>();
        this.categories = new ConcurrentHashMap<>();
        this.filler = new HashSet<>();
        this.ruletrigger = new ConcurrentHashMap<>();
        this.observations = new HashMap<>();
    }

    public SusiMind observe() throws IOException {
        observe(this.initpath);
        observe(this.watchpath);
        return this;
    }
    
    private void observe(File path) throws IOException {
        for (File f: path.listFiles()) {
            if (!f.isDirectory() && f.getName().endsWith(".json")) {
                if (!observations.containsKey(f) || f.lastModified() > observations.get(f)) {
                    observations.put(f, System.currentTimeMillis());
                    try {
                        learn(f);
                    } catch (Throwable e) {
                        DAO.severe(e.getMessage());
                    }
                }
            }
        }
    }
    
    public SusiMind learn(File file) throws JSONException, FileNotFoundException {
        JSONObject json = new JSONObject(new JSONTokener(new FileReader(file)));
        //System.out.println(json.toString(2)); // debug
        return learn(json);
    }
    
    public SusiMind learn(JSONObject json) {

        // initialize temporary json objects
        JSONObject syn = json.has("synonyms") ? json.getJSONObject("synonyms") : new JSONObject();
        JSONArray fill = json.has("filler") ? json.getJSONArray("filler") : new JSONArray();
        JSONObject cat = json.has("categories") ? json.getJSONObject("categories") : new JSONObject();
        JSONArray rules = json.has("rules") ? json.getJSONArray("rules") : new JSONArray();
        
        // add synonyms
        for (String canonical: syn.keySet()) {
            JSONArray a = syn.getJSONArray(canonical);
            a.forEach(synonym -> synonyms.put(((String) synonym).toLowerCase(), canonical));
        }
        
        // add filler
        fill.forEach(word -> filler.add((String) word));
        
        // add categories
        for (String canonical: cat.keySet()) {
            JSONArray a = cat.getJSONArray(canonical);
            a.forEach(synonym -> categories.put(((String) synonym).toLowerCase(), canonical));
        }
        
        // add rules
        rules.forEach(j -> {
            SusiRule rule = new SusiRule((JSONObject) j);
            rule.getKeys().forEach(key -> {
                    Map<Long, SusiRule> l = this.ruletrigger.get(key);
                    if (l == null) {l = new HashMap<>(); this.ruletrigger.put(key, l);}
                    l.put(rule.getID(), rule); 
                });
            });
        
        return this;
    }
    
    public List<SusiRule> associate(String query, int maxcount) {
        // tokenize query to have hint for rule collection
        List<SusiRule> rules = new ArrayList<>();
        token(query).forEach(token -> {Map<Long, SusiRule> r = this.ruletrigger.get(token); if (r != null) rules.addAll(r.values());});

        // add catchall rules always
        Collection<SusiRule> ca = this.ruletrigger.get(SusiRule.CATCHALL_KEY).values(); if (ca != null) rules.addAll(ca);
        
        // create list of all rules that might apply
        TreeMap<Integer, List<SusiRule>> scored = new TreeMap<>();
        rules.forEach(rule -> {
            //System.out.println("rule.phrase-1:" + rule.getPhrases().toString());
            int score = rule.getScore();
            List<SusiRule> r = scored.get(-score);
            if (r == null) {r = new ArrayList<>(); scored.put(-score, r);}
            r.add(rule);
        });

        // make a sorted list of all rules
        rules.clear(); scored.values().forEach(r -> rules.addAll(r));
        
        // test rules and collect those which match up to maxcount
        List<SusiRule> mrules = new ArrayList<>(Math.min(10, maxcount));
        for (SusiRule rule: rules) {
            //System.out.println("rule.phrase-2:" + rule.getPhrases().toString());
            if (rule.getActions().size() == 0) continue;
            if (rule.getActions().get(0).getPhrases().size() == 0) continue;
            if (rule.getActions().get(0).getPhrases().get(0).length() == 0) continue;
            Matcher m = rule.matcher(query);
            if (m == null) continue;
            mrules.add(rule);
            if (mrules.size() >= maxcount) break;
        }
        return mrules;
    }

    private List<String> token(String query) {
        List<String> t = new ArrayList<>();
        query = query.replaceAll("\\?", " ?").replaceAll("\\!", " !").replaceAll("\\.", " .").replaceAll("\\,", " ,").replaceAll("\\;", " ;").replaceAll("\\:", " :").replaceAll("  ", " ");
        String[] u = query.split(" ");
        for (String v: u) {
            String vl = v.toLowerCase();
            if (this.filler.contains(vl)) continue;
            String s = this.synonyms.get(vl);
            if (s != null) vl = s;
            String c = this.categories.get(vl);
            if (c != null) vl = c;
            t.add(vl);
        }
        return t;
    }
    
    /**
     * react on a user input: this causes the selection of deduction rules and the evaluation of the process steps
     * in every rule up to the moment where enough rules have been applied as consideration. The reaction may also
     * cause the evaluation of operational steps which may cause learning effects wihtin the SusiMind.
     * @param query
     * @param maxcount
     * @return
     */
    public List<SusiArgument> react(final String query, int maxcount) {
        List<SusiArgument> answers = new ArrayList<>();
        List<SusiRule> rules = associate(query, 100);
        for (SusiRule rule: rules) {
            SusiArgument argument = rule.consideration(query);
            if (argument != null) answers.add(argument);
            if (answers.size() >= maxcount) break;
        }
        return answers;
    }
    
    public String react(String query) {
        List<SusiArgument> datalist = react(query, 1);
        SusiArgument bestargument = datalist.get(0);
        return bestargument.mindstate().getActions().get(0).apply(bestargument).getStringAttr("expression");
    }
    
    public static void main(String[] args) {
        try {
            File init = new File(new File("conf"), "susi");
            File watch = new File(new File("data"), "susi");
            SusiMind mem = new SusiMind(init, watch);
            mem.learn(new File("conf/susi/susi_cognition_000.json"));
            //System.out.println(mem.answer("who will win euro2016?", 3));
            System.out.println(mem.react("I feel funny"));
            System.out.println(mem.react("Help me!"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
    
}
