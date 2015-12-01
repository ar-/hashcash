/* Penny Post - A postage system for email
 * Copyright (C) 2007  Aliasgar Lokhandwala <d7@freepgs.com> 
 * http://pennypost.sourceforge.net/
 *
 * composeOverlay.js: Overlay for the message compose window
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * static globals, need to be initialized only once
 */
var sPrefs = null;

// First get the preferences service
//taken from example at https://developer.mozilla.org/en/Code_snippets/Preferences
try {
var sPrefs = Services.prefs;
//var sPrefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);

}
catch (ex) {
 dump("failed to preferences services\n");
} 
 
 
//Uses: ppost.js

//Globals
//TB 24 stopped using "gIO Service" and now we need to use "Services.io" instead
//var gIO Service = Components.classes["@mozilla.org/network/io-service;1"].getService(Components.interfaces.nsIIOService);
var gAttachStamp=false;
var gGenStamps='';
var gStrBundle=null;

//listen to the events
addEventListener("compose-send-message", msSendMsg,true);
addEventListener("load", msOnComposeLoad, false);
addEventListener("unload", msOnComposeUnLoad, false);

/**
 * Handles display for stamp & send button
 */
function msMessageComposeOfflineStateChanged(goingOffline)
{
	try {
    	var sendButton = document.getElementById("button-stamp-send");

    	if (goingOffline){
      		sendButton.label = sendButton.getAttribute('later_label');
    	}else{
      		sendButton.label = sendButton.getAttribute('now_label');
    	}
  	} catch(e) {
  		Components.utils.reportError(e);
  	}
}

/**
 * Observer used to detect online/offline state change
 */
var msMessageComposeOfflineObserver = 
{
  observe: function(subject, topic, state) 
  {
    // sanity checks
    if (topic != "network:offline-status-changed") 
      return;
      
    var bIsOffline = state == "offline";
    msMessageComposeOfflineStateChanged(bIsOffline);
  }
}

/**
 * Called automatically when compose window is loaded
 */
function msOnComposeLoad(){
	var observerService = Components.classes["@mozilla.org/observer-service;1"].getService(Components.interfaces.nsIObserverService);
  	observerService.addObserver(msMessageComposeOfflineObserver, "network:offline-status-changed", false);
  
  	// set the initial state of the stamp & send button
  	msMessageComposeOfflineStateChanged(Services.io.offline);
  	
  	gStrBundle = document.getElementById("ppost.string-bundle");
  	
  	//Fix bug#1806927 - Mail stamped accidentially
  	gAttachStamp=false;
}

/**
 * Called automatically when the compose window is unloaded.
 * Note that the compose window is re-used and closing the window 
 * does not unload it, so this event is different from onClose.
 */
function msOnComposeUnLoad(){
	var observerService = Components.classes["@mozilla.org/observer-service;1"].getService(Components.interfaces.nsIObserverService);
	observerService.removeObserver(msMessageComposeOfflineObserver,"network:offline-status-changed");
}

/**
 * Called automatically before sending/saving the message
 */
function msSendMsg() {
    if(gAttachStamp){
        var msgCompFields = gMsgCompose.compFields;
        //add the pre-generated headers
        //msgCompFields.otherRandomHeaders+=gGenStamps+getStampProtocolHeader();
	msgCompFields.setHeader("X-Stampprotocols", getStampProtocolHeader() );
        if( gGenStamps.slice(0,10)==="x-hashcash" ) {
         msgCompFields.setHeader("X-Hashcash",       gGenStamps.slice(12) );
        } else {
	 msgCompFields.setHeader("X-Hashcash",       gGenStamps.slice(10) );
	}
  		//Fix bug#1806927 - Mail stamped accidentially
  		gAttachStamp=false;
    }
}

/**
 * Generates the stamp protocol header which indicates to the recepient the kind of stamp we prefer.
 * Format is x-stampprotocols: <algo1>/<max-supported-ver>/<min-cost>[/<other-params>][/<params>];<algo2>/<max-supported-ver>/<min-cost>[/<params>][/<other-params>] 
 */
function getStampProtocolHeader(){
	var mb = 'mbound:'+Services.prefs.getIntPref('extensions.ppost.mbound.maxver')+':'+Services.prefs.getIntPref('extensions.ppost.mbound.minvalue')+':'+Services.prefs.getIntPref('extensions.ppost.mbound.minpath')+':'+Services.prefs.getIntPref('extensions.ppost.mbound.maxpath');
	var hc = 'hashcash:'+Services.prefs.getIntPref('extensions.ppost.hashcash.maxver')+':'+Services.prefs.getIntPref('extensions.ppost.hashcash.minvalue');
	var rv='';
	var defalgo=Services.prefs.getCharPref('extensions.ppost.defalgo');
	if(defalgo==gStampTypes.S_HASHCASH){
		if(Services.prefs.getBoolPref('extensions.ppost.mbound.enable')){
			return hc + ';' + mb;
		}else{
			return hc;
		}
	}else{
		if(Services.prefs.getBoolPref('extensions.ppost.hashcash.enable')){
			return mb + ';' + hc;
		}else{
			return mb;
		}
	}
}

/**
 * Add pennypost advertisement text at the bottom of the email
 */
function addPennyPostSignature(){
	try{
		var currentEditor = GetCurrentEditor();
		currentEditor.beginTransaction();
		currentEditor.endOfDocument();
		var signature1=gStrBundle.getString("signature1");
		var signature2=gStrBundle.getString("signature2");
		currentEditor.insertLineBreak();
		if (GetCurrentEditorType() == "textmail"){
			currentEditor.insertText("***");
			currentEditor.insertLineBreak();
			currentEditor.insertText(signature1);
			currentEditor.insertLineBreak();
			currentEditor.insertText(signature2);
		}
		else{
			var signature = "<pre class=\"moz-signature\" cols=\"72\"><br/>***<br/>" + signature1 + "<br/>" + signature2 + "</pre>";
			currentEditor.insertHTML(signature);
		}
		currentEditor.endTransaction();
	}catch(ex){
		//ignore, not important
		Components.utils.reportError(ex);
	}
}

/**
 * Menu handler for "Stamp & Send".
 * @param iAlgo 
 * 		The algo to use, 0 to use default algo
 * @param bIsSendNow 
 * 		Set true to send now, false to send later 
 */
function StampSend(iAlgo, bIsSendNow){
	//cant send now if we are offline
	if (bIsSendNow && Services.io && Services.io.offline){
		bIsSendNow=false;
	}

    gAttachStamp=false;
    var obRetVal =        {stamps:'',
                        abort:true};
	    
    var msgCompFields = gMsgCompose.compFields;
    Recipients2CompFields(msgCompFields);                 
    
    //must be modal
    window.openDialog("chrome://ppost/content/stampProgress.xul",
                            "stampProgress", "chrome,modal,titlebar,centerscreen",
                            msgCompFields, iAlgo, Services.prefs, obRetVal);
    if (obRetVal.abort){
        return;
    }else{
        gGenStamps=obRetVal.stamps;
        gAttachStamp=true;
        
        //add promote signature to message body
        var addSignature=Services.prefs.getBoolPref('extensions.ppost.addsignature');
        if(addSignature){
        	addPennyPostSignature();
        }
        
        if(!bIsSendNow)
            SendMessageLater();
        else
            SendMessage();
    }
}
