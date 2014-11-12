local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"
local stdnse = require "stdnse"
local json = require "json"

description = [[
1) Checks for overly permissive <code>/crossdomain.xml</code> files on a web server.

Wildcard detection
------------------
The script will alert if a wildcard entry is found.

Trusted domain inspection
-------------------------
If a <code>/crossdomain.xml</code> file is found that trusts certain domains, 
the script help you determine if any of the domains are available for purchase.

Without any arguments, the script will generate a comma-delimited list of the trusted 
domains so that you can quickly check to see if any of them are available.  This is a 
non intrusive way of getting the data you need, as no external requests are made 

With the liveLookup argument set, the script will automate as much of the domain lookups 
as possible, using instantdomainsearch.com (external requests).  The script will give you 
a comma delimited list of all of the domains it could not automatically look up for you.  
]]

---
--@usage
--nmap --script=http-crossdomain <target>
--nmap --script=http-crossdomain <target> --script-args=liveLookup
--
--@args liveLookup Enables automated domain availability checking via instantdomainsearch.com 
--
--@output
--80/tcp open  http
--| http-crossdomain: 
--|   POTENTIALLY VULNERABLE:
--|     Crossdomain.xml contains <allow-access-from domain="*">
--|       If the FQDN requires authentication and serves sensitive information,
--|       check out the references below for exploitation information.
--|   
--|   POTENTIALLY VULNERABLE:
--|     Crossdomain.xml whitelists domains that could potentially be available for purchase.
--|       If the FQDN requires authentication and serves sensitive information, 
--|       paste the following domains in the URL below to confirm availability.
--|   
--|       DOMAIN LOOKUP URL: https://www.dynadot.com/domain/bulk-search.html
--|   
--|       TRUSTED DOMAINS: domain.com,domain.au,domain.at,domain.be,domain.com.cn,domain.fr,domain.de,domain.com.hk,domain.in,domain1.com,domain2.com,domain3.com,domain4.com,domain5.com,domain6.com,mobile.domain.com,secure.domain.com
--|   
--|   REFERENCES:
--|     https://cwe.mitre.org/data/definitions/942.html 
--|     http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html
--|_
--
--
--80/tcp open  http    
--| http-crossdomain: 
--|   TRUSTED DOMAIN AVAILABLE FOR PURCHASE: domain1.com
--|   TRUSTED DOMAIN AVAILABLE FOR PURCHASE: domain2.com
--|   
--|   POTENTIALLY VULNERABLE (Requires a manual check):
--|     Crossdomain.xml whitelists domains that could potentially be available for purchase.
--|       This script attempted to check all whitelisted domains to see if any of the domains
--|       were available.  Unfortunately, the script was unable to check some domains.
--|       If the FQDN requires authentication and serves sensitive information, you will want
--|       to manually check the remaining domains by browsing to the URL below and pasting
--|       the comma delimited list into the Dynadot bulk domain search tool.
--|   
--|       DOMAIN LOOKUP URL: https://www.dynadot.com/domain/bulk-search.html
--|   
--|       TRUSTED DOMAINS: domain.au,domain.at,domain.be,domain.com.cn,domain.fr,domain.de,domain.com.hk,domain.in
--|      
--|   REFERENCES:
--|     https://cwe.mitre.org/data/definitions/942.html 
--|     http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html
--|_  
---

---
--@Version 1.1
-- Created - 09/22/2014 - v1.0 - Created by Seth Art
-- Revised - 11/12/2014 - v1.1 - Added liveLookup script argument and functionality
---


local liveLookup = stdnse.get_script_args({'http-crossdomain.liveLookup', 'liveLookup'}) or false

author = "Seth Art <sethsec@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "vuln", "safe", "external"}

portrule = shortport.http

local function isempty(s)
  return s == nil or s == ''
end

function inTable(insta_tlds, item)
  for key, value in pairs(insta_tlds) do
    if value == item then return true end
  end
  return false
end

local function checkDomain(domain, tlds)
	--iana_tlds = http.get("data.iana.org", 80, "tlds-alpha-by-domain.txt")
  --print(iana_tlds)
  --print("Inside Checkdomain", domain, tlds)

        local host = "instantdomainsearch.com"
        local port = { number = 443, protocol = "tcp" }
        local path = "/all/" .. domain .. "?/tlds=" .. tlds .. "&limit=1"
        --print(path)

        local response = http.get(host, port.number, path)
        if ( not(response) or response.status ~= 200 ) then
                return false, "Failed to retrieve results"
        end
        --print(response.body)
        local status, json_data = json.parse(response.body)
        if ( not(status) ) then
                return false, "Failed to parse JSON response"
        end
        isRegistered = json_data['isRegistered']
        return isRegistered
end

---
-- Returns the table to be included in the nmap output
-- @param body   The HTTP RESPONSE body containing the contents of crossdomain.xml
---
local function parse_crossdomain(body)
output = {}
local domains = ""
local domainsLiveLookup = ""
local wildcard
-- This defines the list of tlds supported by instantdomainsearch.com.  This is the only search tool i 
-- could find that did not require a user specific API key.  It is not perfect, but it covers most of 
-- the domains I come across.  
insta_tlds= {'com','net','org','co','info','biz','mobi','us','ca','co.uk','in','io','it','pt','me','tv'}

  -- This for loop iterates through each line in the crossdomain.xml file.
  -- If the line does contains allow-access-from, the match extracts the trusted domain
  for line in body:gmatch("<allow%-access%-from(.-)%/>") do

    match = false
    line = line:gsub("^%s*(.-)%s*$", "%1")
    -- This checks to see if the current line contains domain=star
    if line:match("domain%=\"%*\"") then
      table.insert(output,"POTENTIALLY VULNERABLE:")
      table.insert(output,"  Crossdomain.xml contains <allow-access-from domain=\"*\">")
      table.insert(output,"    If the FQDN requires authentication and serves sensitive information,")
      table.insert(output,"    check out the references below for exploitation information.")
    table.insert(output,"")
    else
      line = line:match("domain%=\"(.-)\""):gsub("%*%.", "")
      -- If script-args=liveLookup is set, we need to actively check domain availability.  Otherwise, 
      -- we can just append each new trusted domain to a string that will be sent to the user
      if ( liveLookup ) then
        -- For each of the tlds supported by instantdomainseach.com, check to see if the tld string is 
        -- at the end of the current domain.  If it does, sent it to the checkDomain function  
        for _, tld in ipairs(insta_tlds) do 
          --print ("Test new item from instal_tlds", tld, line)
          -- This next match allows me see if the current value of the variable is at the end of the line
          if line:match("("..tld..")$") then
            --print(line)
            -- This allows me to match only the domain, getting rid of all subdomains. It pulls everything
            -- between the last period and the tld 
            domain, tlds  = line:match("([^.]*).("..tld..")")
            match = true
            --print ("Match", tlds, line)
            break
          end 
        end
        --print ("Match = ", match)
        if not match then
          --print ("No match was detected, adding domain")
          domainsLiveLookup = domainsLiveLookup .. line .. ","
          --print (domainsLiveLookup)
          tlds = "asdfasdf"
        end
        
        --print ("TLDS after foor loop", tlds)
         
        if inTable(insta_tlds, tlds) then
          
          --print (tlds) 
          --local registered, lookedUP  = checkDomain(line)
          local registered, lookedUP  = checkDomain(domain, tlds)

          if not registered then
            table.insert(output, "TRUSTED DOMAIN AVAILABLE FOR PURCHASE: " .. line)
          end
        end

      else
        domains = domains .. line .. ","
      end
    end
  end
  domains = domains:gsub(",$", "")
  domainsLiveLookup = domainsLiveLookup:gsub(",$", "")
  if not isempty(domains) then
    table.insert(output,"POTENTIALLY VULNERABLE:")
    table.insert(output,"  Crossdomain.xml whitelists domains that could potentially be available for purchase.")
    table.insert(output,"    If the FQDN requires authentication and serves sensitive information, ")
    table.insert(output,"    paste the following domains in the URL below to confirm availability.")
    table.insert(output,"")
    table.insert(output,"    DOMAIN LOOKUP URL: https://www.dynadot.com/domain/bulk-search.html")
    table.insert(output,"")
    table.insert(output,"    TRUSTED DOMAINS: " .. domains)
    table.insert(output,"") 
  end

  if not isempty(domainsLiveLookup) then
    table.insert(output,"")
    table.insert(output,"POTENTIALLY VULNERABLE (Requires a manual check):")
    table.insert(output,"  Crossdomain.xml whitelists domains that could potentially be available for purchase.")
    table.insert(output,"    This script attempted to check all whitelisted domains to see if any of the domains")
    table.insert(output,"    were available.  Unfortunately, the script was unable to check some domains.")
    table.insert(output,"    If the FQDN requires authentication and serves sensitive information, you will want")
    table.insert(output,"    to manually check the remaining domains by browsing to the URL below and pasting")
    table.insert(output,"    the comma delimited list into the Dynadot bulk domain search tool.")
    table.insert(output,"")
    table.insert(output,"    DOMAIN LOOKUP URL: https://www.dynadot.com/domain/bulk-search.html")
    table.insert(output,"")
    table.insert(output,"    TRUSTED DOMAINS: " .. domainsLiveLookup)
    table.insert(output,"") 
  end

  if not isempty(output) then
    table.insert(output,"") 
    table.insert(output,"REFERENCES:")
    table.insert(output,"  https://cwe.mitre.org/data/definitions/942.html ")
    table.insert(output,"  http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html")
    table.insert(output,"")
  end 
  return output
end


---
-- Main 
---
action = function(host, port)
  local crossdomain 
  local answer = http.get(host, port, "/crossdomain.xml" )
  if answer.status ~= 200 then
    return nil
  end

  crossdomain = parse_crossdomain(answer.body)

  if crossdomain == 0 then
    return
  end

return crossdomain
end
