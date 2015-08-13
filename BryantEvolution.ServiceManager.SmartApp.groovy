/**
 *  Bryant MyEvolution (Connect)
 *
 *  Copyright 2015 Jason Mok
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 *  Last Updated 7/5/2015
 *
 */
definition(
	name: "Bryant MyEvolution (Connect)",
	namespace: "copy-ninja",
	author: "Jason Mok",
	description: "Connect to Bryant MyEvolution / Carrier MyInfinity to control your thermostats",
	category: "SmartThings Labs",
	iconUrl: "http://smartthings.copyninja.net/icons/Bryant_MyEvolution@1x.png",
	iconX2Url: "http://smartthings.copyninja.net/icons/Bryant_MyEvolution@2x.png",
	iconX3Url: "http://smartthings.copyninja.net/icons/Bryant_MyEvolution@3x.png"
) 


preferences {
	page(name: "prefLogIn", title: "Bryant MyEvolution / Carrier MyInfinity")    
	//page(name: "prefListDevice", title: "Bryant MyEvolution / Carrier MyInfinity")
}

/* Preferences */
def prefLogIn() {
	def showUninstall = username != null && password != null 
	return dynamicPage(name: "prefLogIn", title: "Connect to MyEvolution/MyInfinity", nextPage:"prefListDevice", uninstall:showUninstall, install: false) {
		section("Login Credentials"){
			input("username", "text", title: "Username", description: "MyEvolution/MyInfinity Username (case sensitive)")
			input("password", "password", title: "Password", description: "MyEvolution/MyInfinity password (case sensitive)")
		} 
		section("Brand"){
			input(name: "brand", title: "Brand", type: "enum",  metadata:[values:["Bryant","Carrier"]] )
		}
		section("Advanced Options"){
			input(name: "polling", title: "Server Polling (in Minutes)", type: "int", description: "in minutes", defaultValue: "5" )
			paragraph "This option enables author to troubleshoot if you have problem adding devices. It allows the app to send information exchanged with Bryant/Carrier server to the author. DO NOT ENABLE unless you have contacted author at jason@copyninja.net"
			input(name:"troubleshoot", title: "Troubleshoot", type: "boolean")
		}            
	}
}

def prefListDevice() {
	if (login()) {
		setLookupInfo()
		def thermostatList = getThermostatList()
		if (thermostatList) {
			return dynamicPage(name: "prefListDevice",  title: "Thermostats", install:true, uninstall:true) {
				section("Select which thermostat/zones to use"){
					input(name: "thermostat", type: "enum", required:false, multiple:true, metadata:[values:thermostatList])
				}
			}
		} else {
			return dynamicPage(name: "prefListDevice",  title: "Error!", install:false, uninstall:true) {
				section(""){ paragraph "Could not find any devices "  }
			}
		}
	} else {
		return dynamicPage(name: "prefListDevice",  title: "Error!", install:false, uninstall:true) {
			section(""){ paragraph "The username or password you entered is incorrect. Try again. " }
		}  
	}
}

/* Initialization */
def installed() { initialize() }
def updated() { 
	unsubscribe()
	initialize() 
}
def uninstalled() {
	unschedule()
    unsubscribe()
	getAllChildDevices().each { deleteChildDevice(it.deviceNetworkId) }
}	

def initialize() {
	// Set initial states
	state.polling = [ last: 0, rescheduler: now() ]  
	state.data = [:]
    state.setData = [:]
    setLookupInfo()
    login()
    getThermostatList()
}


/* Access Management */
private login() { 
    if (state.session?.expiration < now()) {
		state.session = [:]
        def apiBody = "data=" + URLEncoder.encode("<credentials><username><![CDATA[" + settings.username + "]]></username><password><![CDATA[" + settings.password + "]]></password></credentials>")
    	apiPost("/users/authenticated", apiBody ) { response ->
            if (response.status == 200) {
            	if (response.data.text() != "Failed") {
                	state.session = [ 
                    	cookie: response.headers.getAt('Set-Cookie').toString().substring(11),
                        accessToken: response.data.text(),
                    	expiration: now() + 600000
                	]
                    log.debug state.session
                    return true
                } else {
                	return false
                }
            } else {
                return false
            }
		} 
    } else { 
		return true
	}
}

/* API Management */
// HTTP GET call
private apiGet(apiPath, callback = {}) {	
	// set up parameters
	def apiParams = [ 
		uri: getApiURL(),
		path: apiPath,
        contentType: "text/xml",
        headers: getApiHeaders("GET",apiPath,""),
	] 	
	try {
		httpGet(apiParams) { response -> callback(response) }
	}	catch (Error e)	{
		log.debug "API Error: $e"
	}
}

// HTTP POST call
private apiPost(apiPath, apiBody, callback = {}) {	
	// set up parameters
	def apiParams = [ 
		uri: getApiURL(),
		path: apiPath,
        contentType: "text/xml",
        headers: getApiHeaders("POST",apiPath,apiBody),
        requestContentType: "application/x-www-form-urlencoded",
        body: apiBody
	] 
	try {
		httpPost(apiParams) { response -> callback(response) }
	}	catch (Error e)	{
		log.debug "API Error: $e"
	}
}
private getApiHeaders(apiMethod,apiPath,apiBody) {
	def apiHeaders = [
    	"Authorization": getApiAuth(apiMethod,apiPath,apiBody),
        "User-Agent": "Mozilla/5.0 (Windows; U; en-US) AppleWebKit/533.19.4 (KHTML, like Gecko) AdobeAIR/18.0",
    ]    
    if (state.session?.expiration > now()) apiHeaders = apiHeaders + ["Set-Cookie": state.session?.cookie]
    return apiHeaders
}
private getApiURL() { return (settings.brand=="Bryant")? ((settings.troubleshoot == "true")?"https://www-app--api-eng-bryant-com-3k2x5garzcxt.runscope.net":"https://www.app-api.eng.bryant.com") : ((settings.troubleshoot == "true")?"https://www-app--api-ing-carrier-com-3k2x5garzcxt.runscope.net":"https://www.app-api.ing.carrier.com") }
private getApiURL(x) { return (settings.brand=="Bryant")? "https://www.app-api.eng.bryant.com": "https://www.app-api.ing.carrier.com" }
private getApiAuth(oauth_httpmethod,oauth_urlPath, oauth_param) {
	def oauth_url = getApiURL(true) + oauth_urlPath.replace("?", "")
	def oauth_version = "1.0"
	def oauth_consumer_key = "8j30j19aj103911h"    
	def oauth_token = settings.username
	def oauth_signature_method = "HMAC-SHA1"
	def oauth_nonce = now().toString()
    def oauth_timestamp = oauth_nonce.substring(0,10)
    def oauth_base = getOAuthBase(oauth_httpmethod, oauth_url, oauth_param, oauth_consumer_key, oauth_nonce, oauth_signature_method, oauth_timestamp, oauth_token, oauth_version)
    //log.debug oauth_base
    def oauth_signature = URLEncoder.encode(getOAuthSignature(oauth_base).toString())
	return "OAuth realm=\"" + oauth_url + "\",oauth_consumer_key=\"" + oauth_consumer_key + "\",oauth_nonce=\"" + oauth_nonce + "\",oauth_signature=\"" + oauth_signature + "\",oauth_signature_method=\"" + oauth_signature_method + "\",oauth_timestamp=\"" + oauth_timestamp + "\",oauth_token=\"" + oauth_token + "\",oauth_version=\"" + oauth_version + "\""
}
private getOAuthBase(oauth_httpmethod, oauth_url, oauth_param, oauth_consumer_key, oauth_nonce, oauth_signature_method, oauth_timestamp, oauth_token, oauth_version) {
	return oauth_httpmethod + "&" + URLEncoder.encode(oauth_url) + "&" + URLEncoder.encode(((!oauth_param?.isEmpty())?(oauth_param + "&"):"") + "oauth_consumer_key=" + oauth_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + "&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + oauth_token + "&oauth_version=" + oauth_version)
}
private getOAuthSignature(oauth_base) {
	def oauth_key = "0f5ur7d89sjv8d45&" 
    oauth_key = (state.session?.accessToken)? (oauth_key + URLEncoder.encode(state.session?.accessToken)) : oauth_key
	javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1")
	mac.init(new javax.crypto.spec.SecretKeySpec(oauth_key.getBytes(), "HmacSHA1"))
	return mac.doFinal(oauth_base.getBytes()).encodeAsBase64()
}

// Listing all the thermostats you have in iComfort
private getThermostatList() { 	    
	def thermostatList = [:]
    def systemsList = [:]
	
	//Get Thermostat Mode lookups
	apiGet("/users/" + settings.username + "/locations") { response ->
    	if (response.status == 200) {
        	response.data.declareNamespace("atom":"http://www.w3.org/2005/Atom")
            response.data.location.each { location -> 
            	location.systems.system.each {
            		systemsList[it.'atom:link'.@title] = it.'atom:link'.@href.text().tokenize("/").last() 
            	}
            }
    	}
	}
    
    systemsList.each { systemName, systemID ->
    	apiGet("/systems/" + systemID + "/status") { response ->
        	if (response.status == 200) {
            	response.data.zones.zone.each { zone ->
                	if (zone.enabled.text() == "on") {
                    	def dni = [ app.id, systemID, zone.'@id'.text().toString() ].join('|')
                        //log.debug systemName.toString() + ": " + zone.name.text().toString()                       
                        
						thermostatList[dni] = systemName.toString() + ": " + zone.name.text().toString()  
                        
                        //Get the state of each device
                        state.data[dni] = [
                            temperature: zone.rt.toInteger(),
                            humidity: zone.rh.toInteger(),
                            coolingSetpoint: zone.clsp.toInteger(),
                            heatingSetpoint: zone.htsp.toInteger(),
                            thermostatFanMode: lookupInfo( "thermostatFanMode", zone.fan.text().toString(), true ),
                            thermostatOperatingState: lookupInfo( "thermostatOperatingState", response.data.mode.text().toString(), true ),
                            thermostatActivityState: zone.currentActivity.text().toString(),
                        ]                        
                    } 
                }
            }
        }
        
        apiGet("/systems/" + systemID) { response ->
        	if (response.status == 200) {
            	response.data.config.zones.zone.each { zone ->
                	if (zone.enabled.text() == "on") {
                    	def dni = [ app.id, systemID, zone.'@id'.text().toString() ].join('|')
                        state.lookup.activity.putAt(dni, [:])
                        state.lookup.coolingSetPointHigh.putAt(dni, (response.data.config.utilityEvent.maxLimit.toInteger() - response.data.config.cfgdead.toInteger()))
						state.lookup.coolingSetPointLow.putAt(dni, response.data.config.utilityEvent.minLimit.toInteger())
						state.lookup.heatingSetPointHigh.putAt(dni, response.data.config.utilityEvent.maxLimit.toInteger())
						state.lookup.heatingSetPointLow.putAt(dni, (response.data.config.utilityEvent.minLimit.toInteger() + response.data.config.cfgdead.toInteger()))
						state.lookup.differenceSetPoint.putAt(dni, response.data.config.cfgdead.toInteger())
                        zone.activities.activity.each { activity -> state.lookup.activity[dni].putAt(activity.'@id'.toString(), "Activity :\n" + activity.'@id'.toString()) }
                        state.data[dni] = state.data[dni] + [ thermostatMode: lookupInfo( "thermostatMode", response.data.config.mode.text().toString(), true ) ]
                    }
                }
            }
        }
    }   
    log.debug thermostatList
	return thermostatList
}

def setLookupInfo() {
	state.lookup = [ 
 		thermostatOperatingState: [:], 
 		thermostatFanMode: [:], 
 		thermostatMode: [:], 
 		activity: [:], 
 		coolingSetPointHigh: [:], 
 		coolingSetPointLow: [:], 
 		heatingSetPointHigh: [:], 
 		heatingSetPointLow: [:], 
 		differenceSetPoint: [:], 
 		temperatureRangeF: [:] 
 	] 
	state.lookup.thermostatMode["off"] = "off"
	state.lookup.thermostatMode["cool"] = "cool"
    state.lookup.thermostatMode["heat"] = "heat"
    state.lookup.thermostatMode["fanonly"] = "off"
    state.lookup.thermostatMode["auto"] = "auto"
    state.lookup.thermostatOperatingState["heat"] = "heating"
    state.lookup.thermostatOperatingState["hpheat"] = "heating"
    state.lookup.thermostatOperatingState["cool"] = "cooling"
    state.lookup.thermostatOperatingState["off"] = "idle"
    state.lookup.thermostatOperatingState["fanonly"] = "fan only"
    state.lookup.thermostatFanMode["off"] = "auto"
    state.lookup.thermostatFanMode["low"] = "circulate"
    state.lookup.thermostatFanMode["med"] = "on"
    state.lookup.thermostatFanMode["high"] = "on"
}

// lookup value translation
def lookupInfo( lookupName, lookupValue, lookupMode ) {
	if (lookupName == "thermostatFanMode") {
		if (lookupMode) {
			return state.lookup.thermostatFanMode.getAt(lookupValue.toString())
		} else {
			return state.lookup.thermostatFanMode.find{it.value==lookupValue.toString()}?.key
		}
	}
	if (lookupName == "thermostatMode") {
		if (lookupMode) {
			return state.lookup.thermostatMode.getAt(lookupValue.toString())
		} else {
			return state.lookup.thermostatMode.find{it.value==lookupValue.toString()}?.key
		}	
	}
	if (lookupName == "thermostatOperatingState") {
		if (lookupMode) {
			return state.lookup.thermostatOperatingState.getAt(lookupValue.toString())
		} else {
			return state.lookup.thermostatOperatingState.find{it.value==lookupValue.toString()}?.key
		}	
	}
}
