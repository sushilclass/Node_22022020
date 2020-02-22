const WebSocket = require('ws')
const fetch = require("node-fetch");
const uuidv4 = require('uuid/v4');
import jwt = require('jsonwebtoken');

let PORT = process.env.PORT || "4002";
let HOST = process.env.HOST || "http://localhost";
//Our tenant id. Not used in development build
let TID = process.env.TID || "7b8f7acc-e1c0-467a-86e9-678144da7881";
//Program will need to work for "production"
let BUILD = process.env.BUILD || "development";
let urlSignatureKeys = process.env.URLSIGNKEYS || 'https://login.microsoftonline.com/common/discovery/keys';

var azureSignatures;
let wss;
let logInputFilename = "wsserver-input.json";
let logOutputFilename = "wsserver-output.json";
var revitJsonObjs: { oid: string, RevitWsSessionId: string, obj: any }[] = [];
import { JsonHelper, Options } from "./components/utils/JsonHelper";

//let envvar = new envVar();

function noop() { }

function heartbeat() {
    //Logger.log("Heartbeat.");
    this.isAlive = true;
}

const interval = setInterval(function ping() {
    wss.clients.forEach(function each(ws) {
        if (ws.isAlive === false) { return ws.terminate(); }
        ws.isAlive = false;
        ws.ping(noop);
    });
}, 30000);



export default class WsServer {
    noop() { }
    start(port) {
        const request = async () => {
            const response = await fetch(urlSignatureKeys);
            //We need to handle when errors on fetch
            azureSignatures = await response.json();
            wss = new WebSocket.Server({
                port,
                perMessageDeflate: {
                    clientNoContextTakeover: true, // Defaults to negotiated value.
                    serverNoContextTakeover: true, // Defaults to negotiated value.
                },
            });

            
            wss.on("connection", function connection(ws) {
                console.log("Connection/Message with client at " + ws._socket.remoteAddress);
                //tokenDecode();
                ws.id = uuidv4();

                let client = ws;
                ws.isAlive = true;
                ws.ping(noop);
                ws.on("message", async function incoming(bufferOne) {

                    let jsonHelper = new JsonHelper();
                    jsonHelper.init(bufferOne);
                    var opt: Options = jsonHelper.getOptions();
                    if (opt.IdToken != null) {
                        let IdToken = tokenDecode(opt.IdToken);
                        if (IdToken != null) {
                            //let IdToken //= jwtDecode(opt.IdToken);
                            let oid = IdToken.oid;
                            if (opt.Action == "setOidRevitClient") {                               
                                ws.userOidRevitClient = oid;
                            }
                            if (opt.FromWebapp==true && ws.userOidWebClient==null) {
                               // console.log("Token :" + JSON.stringify(jsonHelper.obj.IdToken));
                                ws.userOidWebClient = oid;
                            }                            
                            if (opt.Action == "getJsonAll") {
                                actionSendRevitJsonObj(ws, oid);
                            }
                            if (opt.Action == "setParameter" && opt.RevitWsSessionId != null) {
                                var actionWs;
                                if (ws.id === opt.RevitWsSessionId) {
                                    actionWs = getRandomOtherClientId(ws.id);
                                } else {
                                    actionWs = getClientById(wss, opt.RevitWsSessionId)
                                }
                                if (actionWs != null) {
                                    let arrayAction = [opt];
                                    actionWs.send(JSON.stringify(arrayAction));
                                }
                            }
                            if (opt.Action == "clearRevitSelection") {
                                if (oid != null && oid != "") {
                                    let success = clearRevitJsonObj(revitJsonObjs, ws, oid);
                                    if (success) {
                                        updateAssociatedWebClients(oid);
                                    }
                                }
                            }
                            if (opt.Action == "setSelectionObject" && jsonHelper.obj != null) {

                                var revitObj = JSON.parse(opt.Value);
                                console.log("Set Selection object :" + JSON.stringify(revitObj));
                                if (revitObj != null) {
                                    let success = actionRevitSetJsonObj(revitObj, revitJsonObjs, ws, oid);
                                    if (success) {
                                        updateAssociatedWebClients(oid);
                                    }
                                }
                            }

                        }
                    }

                });

                ws.on("error", function connection() {
                    console.log("Connection Error with client at " + ws._socket.remoteAddress);
                });

                ws.on("close", function () {
                    console.log("Connection Closed with client at " + ws._socket.remoteAddress);
                });

                ws.on("open", function () {
                    console.log("Connection Opened:" + Date.now());
                });
                ws.on('pong', heartbeat);
            });
        }
        request();

        //return null if fails
        //returns token if successful
        function tokenDecode(token: string): any {
            let result;
            let tokenSplit = token.split('.');
            // get the decoded payload and header
            var decoded = jwt.decode(token, { complete: true });
            if (decoded != null && decoded.header != null && decoded.payload != null
                && decoded.header.kid != null && decoded.payload.oid != null && tokenSplit.length == 3) {

                if (decoded.payload.tid == TID || BUILD != "production") {
                    for (let index = 0; index < azureSignatures.keys.length; index++) {
                        const azureKid = azureSignatures.keys[index].kid;
                        if (decoded.header.kid == azureKid) {
                            let pubKeys = azureSignatures.keys[index].x5c;
                            //There should only be one
                            for (let index2 = 0; index2 < pubKeys.length; index2++) {
                                const pubKey = `-----BEGIN CERTIFICATE-----\n${pubKeys[index2]}\n-----END CERTIFICATE-----`;

                                try {
                                    //Fails if pubKey is not verified and if token expired.
                                    let tokenResult = jwt.verify(token, pubKey);
                                    //Fail will not go to this next line
                                    result = tokenResult;
                                } catch (err) {
                                    // err
                                }
                            }
                        }
                    }
                } 
                if(BUILD == "tokenTest") {
                    result = decoded.payload;
                }
            }
            return result;
        }

        function actionRevitSetJsonObj(revitObj, _revitJsonObjs, ws, oid): boolean {
            var success: boolean;
            if (oid != null && oid != "") {
                success = true;
                //Checks to see if object as already been set for revit session.
                let update: boolean = hasRevitJsonObj(_revitJsonObjs, ws, oid)
                if (update) {
                    updateRevitJsonObj(revitObj, _revitJsonObjs, ws, oid);
                }
                else {
                    addNewRevitJsonObjs(revitObj, _revitJsonObjs, ws, oid);
                }
            } else {
                success = false;
                ws.send(`[{"action":"displayMessage","value":"Id_Token unknown issue for web GUI. Contact Administrator."}]`);
            }
            return success;
        }

        function updateAssociatedWebClients(oid) {
            let matchingWebClientsWS = getWebClientSessionIdsByOid(wss, oid);
            matchingWebClientsWS.forEach(function (WebClientWS) {
                actionSendRevitJsonObj(WebClientWS, oid);
            });
        }

        function addNewRevitJsonObjs(revitObj, _revitJsonObjs, ws, oid) {
            addSessionIdToRevitJsonObjs(revitObj, ws);
            _revitJsonObjs.push({ oid: oid, RevitWsSessionId: ws.id, obj: revitObj });
        }

        function updateRevitJsonObj(revitObj, _revitJsonObjs, ws, oid) {
            addSessionIdToRevitJsonObjs(revitObj, ws);
            let revitJsonObj = getRevitJsonObj(_revitJsonObjs, ws, oid);
            if (revitJsonObj != null) {
                revitJsonObj.obj = revitObj;
                revitJsonObj.RevitWsSessionId = ws.id;
            }
        }

        function addSessionIdToRevitJsonObjs(revitObj, ws) {
            revitObj.forEach(function (obj) {
                obj.RevitWsSessionId = ws.id;
            });
        }

        function clearRevitJsonObj(_revitJsonObjs, ws, oid): boolean {
            var success: boolean;
            let revitJsonObj = getRevitJsonObj(_revitJsonObjs, ws, oid);
            if (revitJsonObj != null) {
                success = true;
                revitJsonObj.obj = {};
                revitJsonObj.RevitWsSessionId = ws.id;
            } else {
                success = false;
            }
            return success;
        }

        function getRevitJsonObj(_revitJsonObjs, ws, oid): any {
            let revitJsonObjMatch;
            _revitJsonObjs.forEach(function (revitJsonObj) {
                if (revitJsonObj.oid == oid) {
                    revitJsonObjMatch = revitJsonObj;
                }
            });
            return revitJsonObjMatch;
        }

        function hasRevitJsonObj(_revitJsonObjs, ws, oid): boolean {
            let found: boolean = false;
            _revitJsonObjs.forEach(function (revitJsonObj) {
                if (revitJsonObj.oid == oid) {
                    found = true;
                }
            });
            return found;
        }

        function actionSendRevitJsonObj(ws, oid) {
            if (revitJsonObjs.length > 0) {
                let revitObj = findRevitJsonObjByOid(oid);
                if (revitObj != null) {
                    //Should send compress data
                    ws.send(JSON.stringify(revitObj));
                }
            }
        }

        function findRevitJsonObjByOid(oid: string): any {
            var objFound;
            revitJsonObjs.forEach(element => {
                if (element.oid == oid) {
                    objFound = element.obj;
                }
            });
            return objFound;
        }

        function getRandomOtherClientId(id) {
            var wsClient;
            wss.clients.forEach(function each(ws) {
                if (ws.id != id) {
                    wsClient = ws;
                }
            });
            return wsClient;
        }

        function getWebClientSessionIdsByOid(_wss, oid): any[] {
            var wsClient = [];
            _wss.clients.forEach(function each(_ws) {
                if (_ws.userOidWebClient == oid) {
                    wsClient.push(_ws);
                }
            });
            return wsClient;
        }

        function getClientById(_wss, id) {
            var wsClient;
            _wss.clients.forEach(function each(_ws) {
                if (_ws.id == id) {
                    wsClient = _ws;
                }
            });
            return wsClient;
        }
    }

    close() {
        wss.close(() => {

        });
    }



    static async fetchStatic(url) {
        return await fetch(url, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            }
        })
    }
}