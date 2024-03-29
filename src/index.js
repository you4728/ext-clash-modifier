import { Base64 } from "js-base64";
import yaml from "js-yaml";
import "./template.js";
import template from "./template.js";

export default {
  async fetch(request) {
    let { pathname } = new URL(request.url);

    if (pathname.startsWith("/p/")) {
      let filename = pathname.slice(3)
      return fetch(`https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/${filename}`)
    }

    if (!pathname.startsWith("/m/")) {
      return new Response(`error: invalid parameter`, {
        headers: {
          "content-type": "text/plain",
        },
      });
    }

    let configUrl = Base64.decode(pathname.slice(3));

    let resp = await fetch(configUrl);
    let rawConfig = await resp.text();
    let configObj = yaml.load(rawConfig);

    // remove
    template.remove.forEach((key) => {
      if (key in configObj) {
        delete configObj[key];
      }
    });

    // append
    let appendObj = yaml.load(template.append);
    configObj = Object.assign(configObj, appendObj);

    //loadReg
    let loadRegObj = yaml.load(template.loadReg);

    //ISPReg
    let IPLCRegObj = yaml.load(template.IPLCReg);
  

    // replace proxy names
    let proxyName = [];
    configObj["proxies"].forEach((proxyElem) => {
      let i = proxyElem["name"].search(loadRegObj);
      if (i >= 0) {
        proxyName.push(proxyElem["name"]);
      }  
    });

    // replace IPEL proxy names
    let IPLCproxyName = [];
    configObj["proxies"].forEach((proxyElem) => {
      let i = proxyElem["name"].search(IPLCRegObj);
      if (i >= 0) {
        ISPproxyName.push(proxyElem["name"]);
      }  
    });    

    configObj["proxy-groups"].forEach((_, index) => {
      let groupElem = configObj["proxy-groups"][index];

      let j = groupElem["proxies"].indexOf("_PROXY_NAME");
      if (j >= 0) {
        groupElem["proxies"].splice(j, 1, ...proxyName);
      }
      let k = groupElem["proxies"].indexOf("_IPLC_NAME");
      if (k >= 0) {
        groupElem["proxies"].splice(k, 1, ...IPLCproxyName);
      }      
    });

    // replace rule provider proxy
    Object.keys(configObj["rule-providers"]).forEach(index => {
      let providerElem = configObj["rule-providers"][index];
      let providerProxy = new URL(request.url).origin + '/p/'
      providerElem['url'] = providerElem['url'].replace('_PROVIDER_PROXY|', providerProxy)
    });


    let configStr = yaml.dump(configObj);
    return new Response(configStr, {
      headers: resp.headers,
    });
  },
};
