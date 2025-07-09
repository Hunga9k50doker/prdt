const fs = require("fs");
const path = require("path");
const axios = require("axios");
const colors = require("colors");
const { HttpsProxyAgent } = require("https-proxy-agent");
const readline = require("readline");
const user_agents = require("./config/userAgents");
const settings = require("./config/config.js");
const { sleep, loadData, getRandomNumber, saveToken, isTokenExpired, saveJson, getRandomElement } = require("./utils/utils.js");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const { checkBaseUrl } = require("./checkAPI");
const { headers } = require("./core/header.js");
const { showBanner } = require("./core/banner.js");
const localStorage = require("./localStorage.json");
const ethers = require("ethers");
const APIS = require("./utils/endpoints.json");
const { v4: uuidv4 } = require("uuid");

// const querystring = require("querystring");
// let REF_CODE = settings.REF_CODE;
class ClientAPI {
  constructor(itemData, accountIndex, proxy, baseURL) {
    this.headers = headers;
    this.baseURL = baseURL;
    this.baseURL_v2 = settings.BASE_URL_v2;
    this.localItem = null;
    this.itemData = itemData;
    this.accountIndex = accountIndex;
    this.proxy = proxy;
    this.proxyIP = null;
    this.session_name = null;
    this.session_user_agents = this.#load_session_data();
    this.token = null;
    this.localStorage = localStorage;
    // this.provider = new ethers.JsonRpcProvider(settings.RPC_URL);
    this.wallet = new ethers.Wallet(this.itemData.privateKey);
    this.domains = ["@SolarNyx.com", "@OpenMail.pro", "@MailMagnet.co", "@InboxOrigin.com", "@HorizonsPost.com", "@allfreemail.net", "@EasyMailer.live", "@AllWebEmails.com"];
  }

  #load_session_data() {
    try {
      const filePath = path.join(process.cwd(), "session_user_agents.json");
      const data = fs.readFileSync(filePath, "utf8");
      return JSON.parse(data);
    } catch (error) {
      if (error.code === "ENOENT") {
        return {};
      } else {
        throw error;
      }
    }
  }

  #get_random_user_agent() {
    const randomIndex = Math.floor(Math.random() * user_agents.length);
    return user_agents[randomIndex];
  }

  #get_user_agent() {
    if (this.session_user_agents[this.session_name]) {
      return this.session_user_agents[this.session_name];
    }

    console.log(`[Tài khoản ${this.accountIndex + 1}] Tạo user agent...`.blue);
    const newUserAgent = this.#get_random_user_agent();
    this.session_user_agents[this.session_name] = newUserAgent;
    this.#save_session_data(this.session_user_agents);
    return newUserAgent;
  }

  #save_session_data(session_user_agents) {
    const filePath = path.join(process.cwd(), "session_user_agents.json");
    fs.writeFileSync(filePath, JSON.stringify(session_user_agents, null, 2));
  }

  #get_platform(userAgent) {
    const platformPatterns = [
      { pattern: /iPhone/i, platform: "ios" },
      { pattern: /Android/i, platform: "android" },
      { pattern: /iPad/i, platform: "ios" },
    ];

    for (const { pattern, platform } of platformPatterns) {
      if (pattern.test(userAgent)) {
        return platform;
      }
    }

    return "Unknown";
  }

  #set_headers() {
    const platform = this.#get_platform(this.#get_user_agent());
    this.headers["sec-ch-ua"] = `Not)A;Brand";v="99", "${platform} WebView";v="127", "Chromium";v="127`;
    this.headers["sec-ch-ua-platform"] = platform;
    this.headers["User-Agent"] = this.#get_user_agent();
  }

  createUserAgent() {
    try {
      this.session_name = this.itemData.address;
      this.#get_user_agent();
    } catch (error) {
      this.log(`Can't create user agent: ${error.message}`, "error");
      return;
    }
  }

  async log(msg, type = "info") {
    const accountPrefix = `[PRDT][${this.accountIndex + 1}][${this.itemData.address}]`;
    let ipPrefix = "[Local IP]";
    if (settings.USE_PROXY) {
      ipPrefix = this.proxyIP ? `[${this.proxyIP}]` : "[Unknown IP]";
    }
    let logMessage = "";

    switch (type) {
      case "success":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.green;
        break;
      case "error":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.red;
        break;
      case "warning":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.yellow;
        break;
      case "custom":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.magenta;
        break;
      default:
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.blue;
    }
    console.log(logMessage);
  }

  async checkProxyIP() {
    try {
      const proxyAgent = new HttpsProxyAgent(this.proxy);
      const response = await axios.get("https://api.ipify.org?format=json", { httpsAgent: proxyAgent });
      if (response.status === 200) {
        this.proxyIP = response.data.ip;
        return response.data.ip;
      } else {
        throw new Error(`Cannot check proxy IP. Status code: ${response.status}`);
      }
    } catch (error) {
      throw new Error(`Error checking proxy IP: ${error.message}`);
    }
  }

  async makeRequest(
    url,
    method,
    data = {},
    options = {
      retries: 2,
      isAuth: false,
      extraHeaders: {},
      refreshToken: null,
    }
  ) {
    const { retries, isAuth, extraHeaders, refreshToken } = options;

    const headers = {
      ...this.headers,
      ...extraHeaders,
    };

    if (!isAuth && this.token) {
      headers["cookie"] = `${this.token}`;
    }

    let proxyAgent = null;
    if (settings.USE_PROXY) {
      proxyAgent = new HttpsProxyAgent(this.proxy);
    }

    let currRetries = 0,
      errorMessage = "",
      errorStatus = 0;

    do {
      try {
        const response = await axios({
          method,
          url: `${url}`,
          headers,
          timeout: 120000,
          ...(proxyAgent ? { httpsAgent: proxyAgent, httpAgent: proxyAgent } : {}),
          ...(method.toLowerCase() !== "get" ? { data: data } : {}),
        });
        if (response?.data?.data) return { status: response.status, success: true, data: response.data.data };
        return { success: true, data: response.data, status: response.status };
      } catch (error) {
        errorMessage = error?.response?.data || error.message;
        errorStatus = error.status;
        this.log(`Request failed: ${url} | ${JSON.stringify(errorMessage)}...`, "warning");

        if (errorMessage?.message == "User not found") {
          this.log(`Creating new user....`);
          await this.startFarm();
        } else if (error.status === 401) {
          const token = await this.getValidToken(true);
          if (!token) {
            process.exit(1);
          }
          this.token = token;
          return this.makeRequest(url, method, data, options);
        }
        if (error.status === 400) {
          // this.log(`Invalid request for ${url}, maybe have new update from server | contact: https://t.me/airdrophuntersieutoc to get new update!`, "error");
          return { success: false, status: error.status, error: errorMessage, data: null };
        }
        if (error.status === 429) {
          this.log(`Rate limit ${error.message}, waiting 30s to retries`, "warning");
          await sleep(60);
        }
        await sleep(settings.DELAY_BETWEEN_REQUESTS);
        currRetries++;
        if (currRetries > retries) {
          return { status: error.status, success: false, error: errorMessage, data: null };
        }
      }
    } while (currRetries <= retries);

    return { status: errorStatus, success: false, error: errorMessage, data: null };
  }

  getCookieData(setCookie) {
    try {
      if (!(setCookie?.length > 0)) return null;
      let cookie = [];
      const item = JSON.stringify(setCookie);
      // const item =
      const nonceMatch = item.match(/accessToken=([^;]+)/);
      if (nonceMatch && nonceMatch[0]) {
        cookie.push(nonceMatch[0]);
      }
      const nonceMatch_2 = item.match(/refreshToken=([^;]+)/);
      if (nonceMatch_2 && nonceMatch_2[0]) {
        cookie.push(nonceMatch_2[0]);
      }

      const data = cookie.join(";");
      return cookie.length > 0 ? data : null;
    } catch (error) {
      this.log(`Error get cookie: ${error.message}`, "error");
      return null;
    }
  }

  async auth(retries = 5) {
    const result = await this.getNonce();
    if (!result) {
      this.log("Can't get nonce", "error");
      return null;
    }
    const { data, cookie } = result;
    const { message, nonce } = data;
    const signedMessage = await this.wallet.signMessage(message);
    const payload = {
      message: message,
      nonce: nonce,
      signature: signedMessage,
      address: this.itemData.address,
    };
    const url = `${APIS.verify}`;
    const headers = {
      ...this.headers,
      Cookie: cookie,
    };

    let agent = null;
    if (this.proxy && settings.USE_PROXY) {
      agent = new HttpsProxyAgent(this.proxy);
    }

    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const response = await axios.post(url, payload, {
          headers,
          ...(agent ? { httpAgent: agent, httpAgents: agent } : {}),
        });
        const setCookie = response.headers["set-cookie"];
        // const newCookie = this.getCookieData(setCookie);
        if (setCookie.length > 0) {
          return setCookie.join(";");
        }
      } catch (error) {
        if (attempt < retries - 1) {
          await sleep(5);
        } else {
          return null;
        }
      }
    }
    return null;
  }

  async getNonce(retries = 5) {
    const url = `${this.baseURL}/auth/request-message`;
    let agent = null;
    if (this.proxy && settings.USE_PROXY) {
      agent = new HttpsProxyAgent(this.proxy);
    }
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const response = await axios.post(
          url,
          {
            address: this.itemData.address,
            chain: settings.CHAIN_ID || 11155111,
            network: "evm",
          },
          {
            headers: this.headers,
            timeout: 120000,
            ...(agent ? { httpAgent: agent, httpAgents: agent } : {}),
          }
        );
        const setCookie = response.headers["set-cookie"];
        const cookie = this.getCookieData(setCookie);
        return { data: response.data, cookie };
      } catch (error) {
        this.log(`Error get nonce: ${error.message}`, "error");
        if (attempt < retries - 1) {
          await sleep(5);
        } else {
          return null;
        }
      }
    }
  }

  getRandomIpAddress() {
    while (true) {
      const octets = Array.from({ length: 4 }, () => Math.floor(Math.random() * 256));
      const [a, b, c, d] = octets;

      // Loại trừ các dải private và IP không hợp lệ
      if (
        a === 0 ||
        a === 10 ||
        a === 127 ||
        a === 255 || // 0.x.x.x, 10.x.x.x, 127.x.x.x, 255.x.x.x
        (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0 – 100.127.255.255 (CGNAT)
        (a === 169 && b === 254) || // 169.254.x.x (link-local)
        (a === 172 && b >= 16 && b <= 31) || // 172.16.x.x – 172.31.x.x
        (a === 192 && b === 0 && c === 2) || // 192.0.2.x (TEST-NET-1)
        (a === 192 && b === 168) || // 192.168.x.x
        (a === 198 && (b === 18 || b === 19)) || // 198.18.x.x – 198.19.x.x (benchmark)
        (a === 203 && b === 0 && c === 113) || // 203.0.113.x (TEST-NET-3)
        a >= 224 // Multicast & reserved
      ) {
        continue; // random lại
      }
      return octets.join(".");
    }
  }

  async tracking() {
    const payload = {
      uid: Math.random().toString(36).slice(2, 10),
      ipAddress: this.proxyIP || this.getRandomIpAddress(),
      queryString: [{ key: "referralCode", value: settings.REF_CODE }],
      referrer: null,
      userAgent: this.#get_user_agent(),
      updatedAt: Date.now().toString(),
      address: this.itemData.address,
    };

    return this.makeRequest(`https://api-desk.metacrm.inc/api/tracking`, "post", payload, { isAuth: true });
  }
  async getUserData() {
    return this.makeRequest(`${APIS.getUserData}`, "get");
  }

  async checkin() {
    return this.makeRequest(`${APIS.checkin}`, "post", {});
  }

  async sendMail(mail) {
    return this.makeRequest(`${APIS.sendMail}`, "post", {
      email: mail,
      isSolana: "false",
    });
  }

  async verifyMail(token) {
    // e06c372ef385616c291804fb452b65c7d904fc341d5e20f26a7a51a0c0f72992;
    return this.makeRequest(`${APIS.verifyMail}/${token}`, "post", {});
  }

  async startFarm() {
    return this.makeRequest(`${APIS.startMining}`, "post", {
      referralCode: settings.REF_CODE,
    });
  }

  async getValidToken(isNew = false) {
    const existingToken = this.token;
    if (existingToken) {
      const tokens = existingToken.match(/accessToken=([^;]+)/);
      if (tokens && tokens[0]) {
        const accessToken = tokens[0].replace("accessToken=", "");
        const { isExpired: isExp, expirationDate } = isTokenExpired(accessToken);
        this.log(`Access token status: ${isExp ? "Expired".yellow : "Valid".green} | Acess token exp: ${expirationDate}`);
        if (accessToken && !isNew && !isExp) {
          this.log("Using valid token", "success");
          return accessToken;
        }
      }
    }

    this.log("No found token or experied, trying get new token...", "warning");
    const loginRes = await this.auth();
    if (loginRes) {
      await saveJson(this.session_name, JSON.stringify({ token: loginRes }), "localStorage.json");
      return loginRes;
    }

    this.log("Can't get new token...", "warning");
    return null;
  }

  isCheckInTime(nextCheckInActive) {
    if (!nextCheckInActive) return true;
    const nextCheckIn = new Date(nextCheckInActive);
    const now = new Date();
    return now >= nextCheckIn;
  }

  async handleMining(userData) {
    const { nextCheckInActive, miningStartedAt, settings, emailVerified } = userData.user;
    if (!this.isCheckInTime(nextCheckInActive)) {
      return this.log(`Next checkin: ${new Date(nextCheckInActive).toLocaleString()}`, "warning");
    }
    if (!miningStartedAt) {
      const resGt = await this.startFarm();
      if (!resGt.success) this.log(`Can't start farm: ${JSON.stringify(resGt)}`, "warning");
    }

    if (settings.email.address && emailVerified) {
      const resCheckin = await this.checkin();
      if (resCheckin.success) {
        this.log(`Checkin success!`, "success");
      } else {
        this.log(`Failed checkin ${JSON.stringify(resCheckin)}`, "warning");
      }
    } else {
      this.log(`You need verify mail to checkin`, "warning");
    }
    return;
  }

  async generateRandomEmail() {
    const getRandomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
    const getRandomChar = () => String.fromCharCode(getRandomInt(97, 122)); // 'a' to 'z'
    const domains = this.domains;
    const username = Array.from({ length: getRandomInt(5, 8) }, getRandomChar).join("") + getRandomInt(100, 999);
    const { data } = await this.makeRequest("https://temporarymail.com/api/?action=generateRandomName&value=0", "get", null, {
      isAuth: true,
      extraHeaders: {
        referrer: "https://temporarymail.com/en/",

        // "X-API-KEY": settings.API_ID,
      },
    });
    const address = data.address || username;
    // let domains = data.member;
    // if (domains && domains.length == 0) {
    //   const resCreate = await this.createDomain();
    //   domains = [resCreate];
    // }
    // const domainItem = getRandomElement(domains);
    const domain = getRandomElement(domains);
    return `${address}${domain}`;
  }

  async createAccount() {
    try {
      const email = await this.generateRandomEmail();
      this.log(`Requesting email: ${email}`);
      const response = await this.makeRequest(`https://temporarymail.com/api/?action=requestEmailAccess&key=&value=${email}&r=https%3A%2F%2Fwww.bing.com%2F`, "get", null, {
        isAuth: true,
        extraHeaders: {
          referrer: "https://temporarymail.com/en/",
        },
      });

      if (response.success) {
        const { address, secretKey } = response.data;
        return { email: address, secretKey };
      } else {
        this.log(`${JSON.stringify(response.data)}`, "warning");
        return null;
      }
    } catch (error) {
      this.log(`Error request email: ${error.message}`, "warning");
      return null;
    }
  }

  // Get email content
  async getEmailContent(messageId) {
    try {
      const response = await this.makeRequest(`https://temporarymail.com/view/?i=${messageId}&width=0`, "get", null, {
        isAuth: true,
        extraHeaders: {
          referrer: "https://temporarymail.com/en/",
        },
      });

      if (response.success) {
        return response.data.text || response.data.html || JSON.stringify(response.data) || "";
      }
      return "";
    } catch (error) {
      this.log(`Error get content email: ${error.message}`, "warning");
      return "";
    }
  }

  // Get inbox messages
  async getInboxMessages(token) {
    for (let i = 0; i < 15; i++) {
      try {
        const response = await this.makeRequest(`https://temporarymail.com/api/?action=checkInbox&value=${token}`, "get", null, {
          isAuth: true,
          extraHeaders: {
            referrer: "https://temporarymail.com/en/",
          },
        });

        if (response.success) {
          if (response.data?.length == 0) continue;

          const messages = Object.entries(response.data);
          if (messages.length > 0) {
            const latestMessage = messages[0];
            const key = latestMessage[0];
            return { id: key, content: await this.getEmailContent(key) };
          }
        }
        await sleep(1);
      } catch (error) {
        this.log(`Error get inbox message email: ${error.message}`, "warning");
        return null;
      }
    }

    this.log("\x1b[33mNo new emails after 15 seconds.", "warning");
    return null;
  }

  // Extract verification token
  extractVerificationToken(emailText) {
    const tokenRegex = /[?&]token=([a-zA-Z0-9]+)/;
    const match = emailText.match(tokenRegex);

    if (match && match[1]) {
      const token = match[1];
      return token;
    }
    return null;
  }

  // Check latest email
  async checkLatestEmail(email, token) {
    const inboxMessages = await this.getInboxMessages(token);
    if (!inboxMessages) {
      return;
    }

    const verificationToken = this.extractVerificationToken(inboxMessages.content);
    if (verificationToken) {
      const res = await this.verifyMail(verificationToken);
      if (res.success) {
        this.log(`Verify email ${email} success!`, "success");
      } else {
        this.log(`Verify email ${email} failed! | ${JSON.stringify(res)}`, "warning");
      }
    }
  }

  async handleVerifyEmail(userData) {
    const emailAddress = userData.user.settings?.email?.address;
    this.log(`Starting verify email...`);
    if (settings.AUTO_CREATE_EMAIL) {
      const account = await this.createAccount();
      // console.log(account);
      if (!account?.email) {
        return this.log(`Can't create email`, "warning");
      }

      const resultPost = await this.sendMail(account.email);
      if (resultPost.success) {
        await this.checkLatestEmail(account.email, account.secretKey);
      } else {
        if (resultPost?.error?.message?.startsWith("Maximum number of verified emails (3) for domain")) {
          this.log(`${resultPost?.error?.message} | trying other domain...`, "warning");
          this.domains = this.domains.filter((d) => d !== account.email.split("@")[1]);
          if (this.domains.length == 0) {
            return this.log(`No domains avaliable to verify email!`, "warning");
          } else {
            return await this.handleVerifyEmail(userData);
          }
        } else this.log(`Can't send mail ${account.email} to verify | ${JSON.stringify(resultPost)}`, "warning");
      }
    } else {
      let allEmails = loadData("./data/emails.txt");
      const allEmailsVerify = loadData("./data/emailsVerify.txt");
      let emailsHasToken = [];
      const dataEmail = allEmailsVerify.map((e) => {
        const [email, token] = e.split("|");
        if (token) {
          emailsHasToken.push(email);
        }
        return {
          email: email,
          token: token || null,
        };
      });

      allEmails = allEmails.filter((e) => !emailsHasToken.includes(e));

      const emailMatch = dataEmail.find((e) => e.email == emailAddress && emailAddress);
      if (emailMatch && emailMatch?.token) {
        const res = await this.verifyMail(emailMatch?.token);
        if (res.success) {
          this.log(`Verify email ${emailMatch.email} success!`, "success");
        } else {
          this.log(`Verify email ${emailMatch.email} failed! | ${JSON.stringify(res)}`, "warning");
        }
      } else {
        const currEmail = allEmails[this.accountIndex];
        if (currEmail) {
          const resultPost = await this.sendMail(currEmail);
          if (resultPost.success) {
            if (!allEmailsVerify.includes(currEmail)) fs.appendFileSync("./data/emailsVerify.txt", `\n${currEmail}`);
            return this.log(`Please check your email: ${currEmail} and update token into emails.txt, format: email|token`, "success");
          } else {
            if (resultPost?.error?.message?.startsWith("Maximum number of verified emails (3) for domain")) {
              this.log(`${resultPost?.error?.message} | trying change other emails...`, "warning");
              return;
            } else this.log(`Can't send mail ${currEmail} to verify | ${JSON.stringify(resultPost)}`, "warning");
          }
        } else {
          this.log(`Not found email to verify!`, "warning");
        }
      }
    }
    return false;
  }

  async handleSyncData() {
    this.log(`Sync data...`);
    let userData = { success: false, data: null, status: 0 },
      retries = 0;
    do {
      userData = await this.getUserData();
      if (userData?.success) break;
      retries++;
    } while (retries < 1 && userData.status !== 400);

    if (userData?.success) {
      const { minedTokens, referralCode, lastDailyCheckIn, settings, emailVerified } = userData.data.user;
      this.log(
        `Email: ${emailVerified ? settings.email.address : "Not verify"} | Ref code: ${referralCode || "Unknow"} | Last checkin: ${
          (lastDailyCheckIn && new Date(lastDailyCheckIn).toLocaleString()) || "Not yet"
        } | Total PRDT: ${Number(minedTokens).toFixed(6) || 0}`,
        "custom"
      );
    } else {
      this.log("Can't sync new data...skipping", "warning");
    }
    return userData;
  }

  async runAccount() {
    const accountIndex = this.accountIndex;
    this.session_name = this.itemData.address;
    this.localItem = JSON.parse(this.localStorage[this.session_name] || "{}");
    this.token = this.localItem?.token;
    this.#set_headers();
    if (settings.USE_PROXY) {
      try {
        this.proxyIP = await this.checkProxyIP();
      } catch (error) {
        this.log(`Cannot check proxy IP: ${error.message}`, "error");
        return;
      }
      const timesleep = getRandomNumber(settings.DELAY_START_BOT[0], settings.DELAY_START_BOT[1]);
      console.log(`=========Tài khoản ${accountIndex + 1} | ${this.proxyIP} | Bắt đầu sau ${timesleep} giây...`.green);
      await sleep(timesleep);
    }

    const resTrack = await this.tracking();
    if (resTrack.success) {
      this.log(resTrack.data.message || `Tracking IP ${this.proxyIP || "Local"}`);
    }

    const token = await this.getValidToken();
    if (!token) return;
    this.token = token;

    let userData = await this.handleSyncData();
    if (userData.success) {
      await sleep(1);
      if (!userData.data.user.emailVerified && settings.AUTO_REF) {
        await this.handleVerifyEmail(userData.data);
        userData = await this.handleSyncData();
      }
      await sleep(1);
      await this.handleMining(userData.data);
    } else {
      return this.log("Can't get use info...skipping", "error");
    }
  }
}

async function runWorker(workerData) {
  const { itemData, accountIndex, proxy, hasIDAPI } = workerData;
  const to = new ClientAPI(itemData, accountIndex, proxy, hasIDAPI);
  try {
    await Promise.race([to.runAccount(), new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 24 * 60 * 60 * 1000))]);
    parentPort.postMessage({
      accountIndex,
    });
  } catch (error) {
    parentPort.postMessage({ accountIndex, error: error.message });
  } finally {
    if (!isMainThread) {
      parentPort.postMessage("taskComplete");
    }
  }
}

async function main() {
  console.clear();
  showBanner();
  const privateKeys = loadData("./data/privateKeys.txt");
  const proxies = loadData("./data/proxy.txt");

  if (privateKeys.length == 0 || (privateKeys.length > proxies.length && settings.USE_PROXY)) {
    console.log("Số lượng proxy và data phải bằng nhau.".red);
    console.log(`Data: ${privateKeys.length}`);
    console.log(`Proxy: ${proxies.length}`);
    process.exit(1);
  }
  if (!settings.USE_PROXY) {
    console.log(`You are running bot without proxies!!!`.yellow);
  }
  let maxThreads = settings.USE_PROXY ? settings.MAX_THEADS : settings.MAX_THEADS_NO_PROXY;

  const resCheck = await checkBaseUrl();
  if (!resCheck.endpoint) return console.log(`Không thể tìm thấy ID API, có thể lỗi kết nỗi, thử lại sau!`.red);
  console.log(`${resCheck.message}`.yellow);

  const data = privateKeys.map((val, index) => {
    const prvk = val.startsWith("0x") ? val : `0x${val}`;
    const wallet = new ethers.Wallet(prvk);
    const item = {
      address: wallet.address,
      privateKey: prvk,
    };
    new ClientAPI(item, index, proxies[index], resCheck.endpoint, {}).createUserAgent();
    return item;
  });
  await sleep(1);
  while (true) {
    let currentIndex = 0;
    const errors = [];
    while (currentIndex < data.length) {
      const workerPromises = [];
      const batchSize = Math.min(maxThreads, data.length - currentIndex);
      for (let i = 0; i < batchSize; i++) {
        const worker = new Worker(__filename, {
          workerData: {
            hasIDAPI: resCheck.endpoint,
            itemData: data[currentIndex],
            accountIndex: currentIndex,
            proxy: proxies[currentIndex % proxies.length],
          },
        });

        workerPromises.push(
          new Promise((resolve) => {
            worker.on("message", (message) => {
              if (message === "taskComplete") {
                worker.terminate();
              }
              if (settings.ENABLE_DEBUG) {
                console.log(message);
              }
              resolve();
            });
            worker.on("error", (error) => {
              console.log(`Lỗi worker cho tài khoản ${currentIndex}: ${error?.message}`);
              worker.terminate();
              resolve();
            });
            worker.on("exit", (code) => {
              worker.terminate();
              if (code !== 0) {
                errors.push(`Worker cho tài khoản ${currentIndex} thoát với mã: ${code}`);
              }
              resolve();
            });
          })
        );

        currentIndex++;
      }

      await Promise.all(workerPromises);

      if (errors.length > 0) {
        errors.length = 0;
      }

      if (currentIndex < data.length) {
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }
    }

    await sleep(3);
    console.log(`=============${new Date().toLocaleString()} | Hoàn thành tất cả tài khoản | Chờ ${settings.TIME_SLEEP} phút=============`.magenta);
    showBanner();
    await sleep(settings.TIME_SLEEP * 60);
  }
}

if (isMainThread) {
  main().catch((error) => {
    console.log("Lỗi rồi:", error);
    process.exit(1);
  });
} else {
  runWorker(workerData);
}
