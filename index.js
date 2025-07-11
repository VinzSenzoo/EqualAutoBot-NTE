import blessed from "blessed";
import chalk from "chalk";
import figlet from "figlet";
import { ethers } from "ethers";
import fs from "fs";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";
import axios from "axios";

const RPC_URL = "https://testnet.hsk.xyz/";
const CONFIG_FILE = "config.json";
const ROUTER_ADDRESS = "0x88a62f533DdB7ACA1953a39542c7E67Eb7C919EE";
const USDT_ADDRESS = "0x60EFCa24B785391C6063ba37fF917Ff0edEb9f4a";
const HKDA_ADDRESS = "0xE8bbE0E706EbDaB3Be224edf2FE6fFff16df1AC1";
const HKDB_ADDRESS = "0x779CA066b69F4B39cD77bA1a1C4d3c5c097A441e";
const USDC_USDT_POOL = "0xb5de5Fa6436AE3a7E396eF53E0dE0FC5208f61a4"; 
const HKDA_HKDB_POOL = "0x092FadF3fA0c2a721C0Ed51f4b271A0d139191b8"; 
const CHAIN_ID = 133; 

const isDebug = false;

let walletInfo = {
  address: "N/A",
  balanceHSK: "0.0000",
  balanceUSDT: "0.0000",
  balanceHKDA: "0.0000",
  balanceHKDB: "0.0000",
  activeAccount: "N/A"
};
let transactionLogs = [];
let activityRunning = false;
let isCycleRunning = false;
let shouldStop = false;
let dailyActivityInterval = null;
let privateKeys = [];
let proxies = [];
let selectedWalletIndex = 0;
let loadingSpinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const borderBlinkColors = ["cyan", "blue", "magenta", "red", "yellow", "green"];
let borderBlinkIndex = 0;
let blinkCounter = 0;
let spinnerIndex = 0;
let nonceTracker = {};
let hasLoggedSleepInterrupt = false;
let isHeaderRendered = false;
let activeProcesses = 0;

let dailyActivityConfig = {
  swapRepetitions: 1,
  minUsdtSwap: 5,
  maxUsdtSwap: 10,
  minHkdaSwap: 40,
  maxHkdaSwap: 76,
  minHkdbSwap: 40,
  maxHkdbSwap: 76,
  addLpRepetitions: 1,
  minHkdaLp: 5,
  maxHkdaLp: 10,
  minHkdbLp: 5,
  maxHkdbLp: 10
};

const tokenNames = {
  [USDT_ADDRESS]: "USDT",
  [HKDA_ADDRESS]: "HKDA",
  [HKDB_ADDRESS]: "HKDB"
};

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const data = fs.readFileSync(CONFIG_FILE, "utf8");
      const config = JSON.parse(data);
      dailyActivityConfig.swapRepetitions = Number(config.swapRepetitions) || 1;
      dailyActivityConfig.minUsdtSwap = Number(config.minUsdtSwap) || 5;
      dailyActivityConfig.maxUsdtSwap = Number(config.maxUsdtSwap) || 10;
      dailyActivityConfig.minHkdaSwap = Number(config.minHkdaSwap) || 40;
      dailyActivityConfig.maxHkdaSwap = Number(config.maxHkdaSwap) || 76;
      dailyActivityConfig.minHkdbSwap = Number(config.minHkdbSwap) || 40;
      dailyActivityConfig.maxHkdbSwap = Number(config.maxHkdbSwap) || 76;
      dailyActivityConfig.addLpRepetitions = Number(config.addLpRepetitions) || 1;
      dailyActivityConfig.minHkdaLp = Number(config.minHkdaLp) || 5;
      dailyActivityConfig.maxHkdaLp = Number(config.maxHkdaLp) || 10;
      dailyActivityConfig.minHkdbLp = Number(config.minHkdbLp) || 5;
      dailyActivityConfig.maxHkdbLp = Number(config.maxHkdbLp) || 10;
    } else {
      addLog("No config file found, using default settings.", "info");
    }
  } catch (error) {
    addLog(`Failed to load config: ${error.message}`, "error");
  }
}

function saveConfig() {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(dailyActivityConfig, null, 2));
    addLog("Configuration saved successfully.", "success");
  } catch (error) {
    addLog(`Failed to save config: ${error.message}`, "error");
  }
}

async function makeJsonRpcCall(method, params) {
  try {
    const proxyUrl = proxies[selectedWalletIndex % proxies.length] || null;
    const agent = createAgent(proxyUrl);
    const response = await axios.post(RPC_URL, {
      jsonrpc: "2.0",
      method,
      params
    }, {
      headers: { "Content-Type": "application/json" },
      httpsAgent: agent
    });
    const data = response.data;
    if (data.error) {
      throw new Error(`RPC Error: ${data.error.message} (code: ${data.error.code})`);
    }
    if (!data.result && data.result !== "") {
      throw new Error("No result in RPC response");
    }
    return data.result;
  } catch (error) {
    const errorMessage = error.response
      ? `HTTP ${error.response.status}: ${error.message}`
      : error.message;
    addLog(`JSON-RPC call failed (${method}): ${errorMessage}`, "error");
    throw error;
  }
}

process.on("unhandledRejection", (reason, promise) => {
  addLog(`Unhandled Rejection at: ${promise}, reason: ${reason.message || reason}`, "error");
});

process.on("uncaughtException", (error) => {
  addLog(`Uncaught Exception: ${error.message}\n${error.stack}`, "error");
  process.exit(1);
});

function getShortAddress(address) {
  return address ? address.slice(0, 6) + "..." + address.slice(-4) : "N/A";
}

function addLog(message, type = "info") {
  if (type === "debug" && !isDebug) return;
  const timestamp = new Date().toLocaleTimeString("id-ID", { timeZone: "Asia/Jakarta" });
  let coloredMessage;
  switch (type) {
    case "error":
      coloredMessage = chalk.redBright(message);
      break;
    case "success":
      coloredMessage = chalk.greenBright(message);
      break;
    case "wait":
      coloredMessage = chalk.yellowBright(message);
      break;
    case "info":
      coloredMessage = chalk.whiteBright(message);
      break;
    case "delay":
      coloredMessage = chalk.cyanBright(message);
      break;
    case "debug":
      coloredMessage = chalk.blueBright(message);
      break;
    default:
      coloredMessage = chalk.white(message);
  }
  const logMessage = `[${timestamp}] ${coloredMessage}`;
  transactionLogs.push(logMessage);
  updateLogs();
}

function getShortHash(hash) {
  return hash.slice(0, 6) + "..." + hash.slice(-4);
}

function clearTransactionLogs() {
  transactionLogs = [];
  logBox.setContent('');
  logBox.scrollTo(0);
  addLog("Transaction logs cleared.", "success");
}

function loadPrivateKeys() {
  try {
    const data = fs.readFileSync("pk.txt", "utf8");
    privateKeys = data.split("\n").map(key => key.trim()).filter(key => key.match(/^(0x)?[0-9a-fA-F]{64}$/));
    if (privateKeys.length === 0) throw new Error("No valid private keys in pk.txt");
    addLog(`Loaded ${privateKeys.length} private keys from pk.txt`, "success");
  } catch (error) {
    addLog(`Failed to load private keys: ${error.message}`, "error");
    privateKeys = [];
  }
}

function loadProxies() {
  try {
    if (fs.existsSync("proxy.txt")) {
      const data = fs.readFileSync("proxy.txt", "utf8");
      proxies = data.split("\n").map(proxy => proxy.trim()).filter(proxy => proxy);
      if (proxies.length === 0) throw new Error("No proxy found in proxy.txt");
      addLog(`Loaded ${proxies.length} proxies from proxy.txt`, "success");
    } else {
      addLog("No proxy.txt found, running without proxy.", "info");
    }
  } catch (error) {
    addLog(`Failed to load proxy: ${error.message}`, "info");
    proxies = [];
  }
}

function createAgent(proxyUrl) {
  if (!proxyUrl) return null;
  if (proxyUrl.startsWith("socks")) {
    return new SocksProxyAgent(proxyUrl);
  } else {
    return new HttpsProxyAgent(proxyUrl);
  }
}

function getProviderWithProxy(proxyUrl, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const agent = createAgent(proxyUrl);
      const fetchOptions = agent ? { agent } : {};
      const provider = new ethers.JsonRpcProvider(RPC_URL, { chainId: CHAIN_ID, name: "HSK Testnet" }, { fetchOptions });
      provider.getNetwork().then(network => {
        if (Number(network.chainId) !== CHAIN_ID) {
          throw new Error(`Network chain ID mismatch: expected ${CHAIN_ID}, got ${network.chainId}`);
        }
      }).catch(err => {
        throw err;
      });
      return provider;
    } catch (error) {
      addLog(`Attempt ${attempt}/${maxRetries} failed to initialize provider: ${error.message}`, "error");
      if (attempt < maxRetries) sleep(1000);
    }
  }
  try {
    addLog(`Proxy failed, falling back to direct connection`, "warn");
    const provider = new ethers.JsonRpcProvider(RPC_URL, { chainId: CHAIN_ID, name: "HSK Testnet" });
    provider.getNetwork().then(network => {
      if (Number(network.chainId) !== CHAIN_ID) {
        throw new Error(`Network chain ID mismatch: expected ${CHAIN_ID}, got ${network.chainId}`);
      }
    }).catch(err => {
      throw err;
    });
    return provider;
  } catch (error) {
    addLog(`Fallback failed: ${error.message}`, "error");
    throw error;
  }
}

async function sleep(ms) {
  if (shouldStop) {
    if (!hasLoggedSleepInterrupt) {
      addLog("Process stopped successfully.", "info");
      hasLoggedSleepInterrupt = true;
    }
    return;
  }
  activeProcesses++;
  try {
    await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        resolve();
      }, ms);
      const checkStop = setInterval(() => {
        if (shouldStop) {
          clearTimeout(timeout);
          clearInterval(checkStop);
          if (!hasLoggedSleepInterrupt) {
            addLog("Process interrupted.", "info");
            hasLoggedSleepInterrupt = true;
          }
          resolve();
        }
      }, 100);
    });
  } catch (error) {
    addLog(`Sleep error: ${error.message}`, "error");
  } finally {
    activeProcesses = Math.max(0, activeProcesses - 1);
  }
}

async function updateWalletData() {
  const tokenAbi = ["function balanceOf(address) view returns (uint256)"];
  const walletDataPromises = privateKeys.map(async (privateKey, i) => {
    try {
      const proxyUrl = proxies[i % proxies.length] || null;
      const provider = getProviderWithProxy(proxyUrl);
      const wallet = new ethers.Wallet(privateKey, provider);

      const hskBalance = await provider.getBalance(wallet.address);
      const usdtContract = new ethers.Contract(USDT_ADDRESS, tokenAbi, provider);
      const usdtBalance = await usdtContract.balanceOf(wallet.address);
      const hkdaContract = new ethers.Contract(HKDA_ADDRESS, tokenAbi, provider);
      const hkdaBalance = await hkdaContract.balanceOf(wallet.address);
      const hkdbContract = new ethers.Contract(HKDB_ADDRESS, tokenAbi, provider);
      const hkdbBalance = await hkdbContract.balanceOf(wallet.address);

      const formattedHSK = Number(ethers.formatEther(hskBalance)).toFixed(4);
      const formattedUSDT = Number(ethers.formatUnits(usdtBalance, 6)).toFixed(4);
      const formattedHKDA = Number(ethers.formatUnits(hkdaBalance, 18)).toFixed(4);
      const formattedHKDB = Number(ethers.formatUnits(hkdbBalance, 18)).toFixed(4);

      const formattedEntry = `${i === selectedWalletIndex ? "→ " : "  "}${chalk.bold.magentaBright(getShortAddress(wallet.address))} ${chalk.bold.cyanBright(formattedHSK)} ${chalk.bold.cyanBright(formattedUSDT)} ${chalk.bold.cyanBright(formattedHKDA)} ${chalk.bold.cyanBright(formattedHKDB)}`;

      if (i === selectedWalletIndex) {
        walletInfo.address = wallet.address;
        walletInfo.activeAccount = `Account ${i + 1}`;
        walletInfo.balanceHSK = formattedHSK;
        walletInfo.balanceUSDT = formattedUSDT;
        walletInfo.balanceHKDA = formattedHKDA;
        walletInfo.balanceHKDB = formattedHKDB;
      }
      return formattedEntry;
    } catch (error) {
      addLog(`Failed to fetch wallet data for account #${i + 1}: ${error.message}`, "error");
      return `${i === selectedWalletIndex ? "→ " : "  "}N/A`;
    }
  });
  try {
    const walletData = await Promise.all(walletDataPromises);
    addLog("Wallet data updated.", "success");
    return walletData;
  } catch (error) {
    addLog(`Wallet data update failed: ${error.message}`, "error");
    return [];
  }
}

async function getNextNonce(provider, walletAddress) {
  if (shouldStop) {
    addLog("Nonce fetch stopped due to stop request.", "info");
    throw new Error("Process stopped");
  }
  if (!walletAddress || !ethers.isAddress(walletAddress)) {
    addLog(`Invalid wallet address: ${walletAddress}`, "error");
    throw new Error("Invalid wallet address");
  }
  try {
    const pendingNonce = await provider.getTransactionCount(walletAddress, "pending");
    const lastUsedNonce = nonceTracker[walletAddress] || pendingNonce - 1;
    const nextNonce = Math.max(pendingNonce, lastUsedNonce + 1);
    nonceTracker[walletAddress] = nextNonce;
    addLog(`Debug: Fetched nonce ${nextNonce} for ${getShortAddress(walletAddress)}`, "debug");
    return nextNonce;
  } catch (error) {
    addLog(`Failed to fetch nonce for ${getShortAddress(walletAddress)}: ${error.message}`, "error");
    throw error;
  }
}

async function swap(wallet, fromToken, toToken, amount) {
  try {
    if (!wallet.address || !ethers.isAddress(wallet.address)) {
      throw new Error(`Invalid wallet address: ${wallet.address}`);
    }
    if (!ethers.isAddress(fromToken) || !ethers.isAddress(toToken)) {
      throw new Error(`Invalid token addresses: fromToken=${fromToken}, toToken=${toToken}`);
    }
    const fromName = tokenNames[fromToken];
    const toName = tokenNames[toToken];
    addLog(`Debug: Building swap transaction for amount ${amount} from ${fromName} to ${toName}`, "debug");

    const tokenAbi = [
      "function allowance(address owner, address spender) view returns (uint256)",
      "function approve(address spender, uint256 amount) returns (bool)",
      "function balanceOf(address) view returns (uint256)"
    ];
    const fromTokenContract = new ethers.Contract(fromToken, tokenAbi, wallet);

    const decimals = fromToken === USDT_ADDRESS ? 6 : 18;
    const amountIn = ethers.parseUnits(amount.toString(), decimals);
    addLog(`Debug: Amount in wei: ${amountIn.toString()}`, "debug");

    const balance = await fromTokenContract.balanceOf(wallet.address);
    if (balance < amountIn) {
      throw new Error(`Insufficient balance: ${ethers.formatUnits(balance, decimals)} available, ${amount} required`);
    }

    const allowance = await fromTokenContract.allowance(wallet.address, ROUTER_ADDRESS);
    addLog(`Debug: Allowance: ${allowance.toString()}`, "debug");
    if (allowance < amountIn) {
      addLog(`Approving router to spend ${amount} ${fromName}`, "info");
      const approveTx = await fromTokenContract.approve(ROUTER_ADDRESS, amountIn, { gasLimit: 100000 });
      const approveReceipt = await approveTx.wait();
      if (approveReceipt.status === 0) {
        throw new Error("Approval transaction reverted");
      }
      addLog("Approval successful", "success");
    }

    const methodId = "0x76f6dece";
    let poolIn, poolOut, index;
    if (fromToken === USDT_ADDRESS) {
      poolIn = USDC_USDT_POOL;
      poolOut = HKDA_HKDB_POOL;
      index = toToken === HKDA_ADDRESS ? "0x0" : "0x1";
    } else {
      poolIn = HKDA_HKDB_POOL;
      poolOut = USDC_USDT_POOL;
      index = "0x1";
    }
    const poolInHex = ethers.zeroPadValue(poolIn, 32).slice(2);
    const poolOutHex = ethers.zeroPadValue(poolOut, 32).slice(2);
    const amountInHex = ethers.zeroPadValue(ethers.toBeHex(amountIn), 32).slice(2);
    let amountOutMin, amountOutMinHex;

    if (fromToken === USDT_ADDRESS) {
      const defaultOutput = (amount * 7.9299514871538083099 * 0.95).toFixed(3);
      amountOutMin = ethers.parseUnits(defaultOutput, 18);
      amountOutMinHex = ethers.zeroPadValue(ethers.toBeHex(amountOutMin), 32).slice(2);
      addLog(`Debug: amountOutMin: ${defaultOutput} ${toName} (${amountOutMinHex})`, "debug");
    } else {
      const defaultOutput = (amount * 0.1259 * 0.95).toFixed(3);
      amountOutMin = ethers.parseUnits(defaultOutput, 6);
      amountOutMinHex = ethers.zeroPadValue(ethers.toBeHex(amountOutMin), 32).slice(2);
      addLog(`Debug: amountOutMin: ${defaultOutput} ${toName} (${amountOutMinHex})`, "debug");
    }

    const pathOffset = "00000000000000000000000000000000000000000000000000000000000000a0";
    const pathLength = "0000000000000000000000000000000000000000000000000000000000000002";
    const pathToken1 = "0000000000000000000000000000000000000000000000000000000000000000";
    const pathToken2 = amountInHex;
    const inputData = `${methodId}${poolInHex}${pathOffset}${poolOutHex}${ethers.zeroPadValue(ethers.toBeHex(index), 32).slice(2)}${amountOutMinHex}${pathLength}${pathToken1}${pathToken2}`;
    addLog(`Debug: Input data: ${inputData}`, "debug");

    if (!inputData || inputData === methodId) {
      throw new Error("Failed to construct valid input data for swap");
    }

    const pendingTxs = await wallet.provider.send("eth_getBlockByNumber", ["pending", true]);
    const pendingTxsForWallet = pendingTxs.transactions.filter(tx => tx.from.toLowerCase() === wallet.address.toLowerCase());
    addLog(`Debug: Pending transactions for ${wallet.address}: ${JSON.stringify(pendingTxsForWallet.map(tx => tx.hash))}`, "debug");

    let sentTx;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const nonce = await getNextNonce(wallet.provider, wallet.address);
        addLog(`Debug: Fetched nonce ${nonce} for ${wallet.address}`, "debug");
        let gasPrice;
        try {
          const feeData = await wallet.provider.getFeeData();
          const rawGasPrice = Number(ethers.formatUnits(feeData.gasPrice || ethers.parseUnits("0.0015", "gwei"), "gwei")) * 1.5;
          gasPrice = ethers.parseUnits(rawGasPrice.toFixed(6), "gwei");
        } catch (e) {
          addLog(`Debug: Failed to parse gasPrice, using default 0.0015 Gwei: ${e.message}`, "warn");
          gasPrice = ethers.parseUnits("0.0015", "gwei");
        }
        addLog(`Debug: Using gasPrice: ${ethers.formatUnits(gasPrice, "gwei")} Gwei`, "debug");

        const tx = {
          to: ROUTER_ADDRESS,
          data: inputData,
          gasLimit: ethers.toBigInt(400000),
          chainId: CHAIN_ID,
          nonce: nonce,
          gasPrice: gasPrice
        };
        addLog(`Debug: Transaction object (attempt ${attempt}): ${JSON.stringify(tx, (key, value) => typeof value === 'bigint' ? value.toString() : value)}`, "debug");
        if (!tx.data || tx.data === "0x") {
          throw new Error("Transaction data is empty or invalid");
        }
        try {
          await wallet.provider.call({
            to: ROUTER_ADDRESS,
            data: inputData,
            from: wallet.address,
            gasLimit: ethers.toBigInt(400000),
            gasPrice: gasPrice
          });
          addLog("Debug: eth_call simulation successful", "debug");
        } catch (error) {
          addLog(`Debug: eth_call simulation failed: ${error.message}`, "error");
          if (error.data) {
            addLog(`Debug: Revert data: ${error.data}`, "error");
          }
        }

        const signedTx = await wallet.signTransaction(tx);
        if (!signedTx || signedTx === "0x") {
          throw new Error("Signed transaction is empty or invalid");
        }

        await new Promise(resolve => setTimeout(resolve, 3000));
        const txHash = await wallet.provider.send("eth_sendRawTransaction", [signedTx]);
        addLog(`Swap Transaction sent.. Hash: ${getShortHash(txHash)}`, "success");

        sentTx = { hash: txHash, data: tx.data, wait: async () => await wallet.provider.waitForTransaction(txHash) };
        break;
      } catch (error) {
        addLog(`Attempt ${attempt}/3 failed: ${error.message}`, "error");
        if (error.message.includes("replacement fee too low")) {
          addLog("Increasing gasPrice for next attempt", "warn");
          await sleep(5000);
          continue;
        }
        if (attempt < 3) {
          await sleep(5000);
          continue;
        }
        throw error;
      }
    }

    if (!sentTx) {
      throw new Error("Failed to send transaction after all attempts");
    }

    const receipt = await sentTx.wait();
    if (receipt.status === 0) {
      addLog(`Swap transaction reverted: ${JSON.stringify(receipt)}`, "error");
      throw new Error(`Transaction reverted: ${receipt.revertReason || 'No revert reason provided'}`);
    }

    addLog(`Swap ${amount} ${fromName} to ${toName} Successfully!`, "success");
  } catch (error) {
    addLog(`Swap operation failed: ${error.message}`, "error");
    if (error.reason) {
      addLog(`Revert reason: ${error.reason}`, "error");
    }
    if (error.receipt) {
      addLog(`Transaction receipt: ${JSON.stringify(error.receipt)}`, "debug");
    }
    if (error.data) {
      addLog(`Revert data: ${error.data}`, "error");
    }
    throw error;
  }
}

async function addLp(wallet) {
  try {
    if (!wallet.address || !ethers.isAddress(wallet.address)) {
      throw new Error(`Invalid wallet address: ${wallet.address}`);
    }
    addLog(`Debug: Building add LP transaction`, "debug");

    const tokenAbi = [
      "function allowance(address owner, address spender) view returns (uint256)",
      "function approve(address spender, uint256 amount) returns (bool)",
      "function balanceOf(address) view returns (uint256)"
    ];

    const hkdaContract = new ethers.Contract(HKDA_ADDRESS, tokenAbi, wallet);
    const hkdbContract = new ethers.Contract(HKDB_ADDRESS, tokenAbi, wallet);

    const amountHKDA = (Math.random() * (dailyActivityConfig.maxHkdaLp - dailyActivityConfig.minHkdaLp) + dailyActivityConfig.minHkdaLp).toFixed(3);
    const amountHKDB = (Math.random() * (dailyActivityConfig.maxHkdbLp - dailyActivityConfig.minHkdbLp) + dailyActivityConfig.minHkdbLp).toFixed(3);

    const amountHKDAWei = ethers.parseUnits(amountHKDA, 18);
    const amountHKDBWei = ethers.parseUnits(amountHKDB, 18);

    addLog(`Adding liquidity for HKDA & HKDB: ${amountHKDA} HKDA and ${amountHKDB} HKDB`, "info");
    addLog(`Debug: Amount HKDA: ${amountHKDA} (${amountHKDAWei.toString()})`, "debug");
    addLog(`Debug: Amount HKDB: ${amountHKDB} (${amountHKDBWei.toString()})`, "debug");

    const balanceHKDA = await hkdaContract.balanceOf(wallet.address);
    const balanceHKDB = await hkdbContract.balanceOf(wallet.address);
    if (balanceHKDA < amountHKDAWei) {
      throw new Error(`Insufficient HKDA balance: ${ethers.formatUnits(balanceHKDA, 18)} available, ${amountHKDA} required`);
    }
    if (balanceHKDB < amountHKDBWei) {
      throw new Error(`Insufficient HKDB balance: ${ethers.formatUnits(balanceHKDB, 18)} available, ${amountHKDB} required`);
    }

    let allowanceHKDA = await hkdaContract.allowance(wallet.address, HKDA_HKDB_POOL);
    if (allowanceHKDA < amountHKDAWei) {
      addLog(`Approving HKDA to spend ${amountHKDA}`, "info");
      const approveTxHKDA = await hkdaContract.approve(HKDA_HKDB_POOL, amountHKDAWei, { gasLimit: 100000 });
      const approveReceiptHKDA = await approveTxHKDA.wait();
      if (approveReceiptHKDA.status === 0) {
        throw new Error("Approval transaction for HKDA reverted");
      }
      addLog("HKDA approval successful", "success");
    }

    let allowanceHKDB = await hkdbContract.allowance(wallet.address, HKDA_HKDB_POOL);
    if (allowanceHKDB < amountHKDBWei) {
      addLog(`Approving HKDB to spend ${amountHKDB}`, "info");
      const approveTxHKDB = await hkdbContract.approve(HKDA_HKDB_POOL, amountHKDBWeiecc, { gasLimit: 100000 });
      const approveReceiptHKDB = await approveTxHKDB.wait();
      if (approveReceiptHKDB.status === 0) {
        throw new Error("Approval transaction for HKDB reverted");
      }
      addLog("HKDB approval successful", "success");
    }

    const methodId = "0xc5bb3168";
    const arg0 = [
      amountHKDAWei.toString(),
      amountHKDBWei.toString(),
      "0",
      "0"
    ];
    const arg1 = "0";
    const encodedArg0 = ethers.AbiCoder.defaultAbiCoder().encode(["uint256[]"], [arg0]);
    const encodedArg1 = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [arg1]);
    const inputData = methodId + encodedArg0.slice(2) + encodedArg1.slice(2);
    addLog(`Debug: Input data: ${inputData}`, "debug");

    const pendingTxs = await wallet.provider.send("eth_getBlockByNumber", ["pending", true]);
    const pendingTxsForWallet = pendingTxs.transactions.filter(tx => tx.from.toLowerCase() === wallet.address.toLowerCase());
    addLog(`Debug: Pending transactions for ${wallet.address}: ${JSON.stringify(pendingTxsForWallet.map(tx => tx.hash))}`, "debug");

    let sentTx;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const nonce = await getNextNonce(wallet.provider, wallet.address);
        addLog(`Debug: Fetched nonce ${nonce} for ${wallet.address}`, "debug");
        let gasPrice;
        try {
          const feeData = await wallet.provider.getFeeData();
          const rawGasPrice = Number(ethers.formatUnits(feeData.gasPrice || ethers.parseUnits("0.0015", "gwei"), "gwei")) * 1.5;
          gasPrice = ethers.parseUnits(rawGasPrice.toFixed(6), "gwei");
        } catch (e) {
          addLog(`Debug: Failed to parse gasPrice, using default 0.0015 Gwei: ${e.message}`, "warn");
          gasPrice = ethers.parseUnits("0.0015", "gwei");
        }
        addLog(`Debug: Using gasPrice: ${ethers.formatUnits(gasPrice, "gwei")} Gwei`, "debug");

        const tx = {
          to: HKDA_HKDB_POOL,
          data: inputData,
          gasLimit: ethers.toBigInt(400000),
          chainId: CHAIN_ID,
          nonce: nonce,
          gasPrice: gasPrice
        };
        addLog(`Debug: Transaction object (attempt ${attempt}): ${JSON.stringify(tx, (key, value) => typeof value === 'bigint' ? value.toString() : value)}`, "debug");

        if (!tx.data || tx.data === "0x") {
          throw new Error("Transaction data is empty or invalid");
        }

        try {
          await wallet.provider.call({
            to: HKDA_HKDB_POOL,
            data: inputData,
            from: wallet.address,
            gasLimit: ethers.toBigInt(400000),
            gasPrice: gasPrice
          });
          addLog("Debug: eth_call simulation successful", "debug");
        } catch (error) {
          addLog(`Debug: eth_call simulation failed: ${error.message}`, "error");
          if (error.data) {
            addLog(`Debug: Revert data: ${error.data}`, "error");
          }
        }

        const signedTx = await wallet.signTransaction(tx);

        if (!signedTx || signedTx === "0x") {
          throw new Error("Signed transaction is empty or invalid");
        }

        await new Promise(resolve => setTimeout(resolve, 3000));
        const txHash = await wallet.provider.send("eth_sendRawTransaction", [signedTx]);
        addLog(`Add LP transaction sent: ${getShortHash(txHash)}`, "success");

        sentTx = { hash: txHash, data: tx.data, wait: async () => await wallet.provider.waitForTransaction(txHash) };
        break;
      } catch (error) {
        addLog(`Attempt ${attempt}/3 failed: ${error.message}`, "error");
        if (error.message.includes("replacement fee too low")) {
          addLog("Increasing gasPrice for next attempt", "warn");
          await sleep(5000);
          continue;
        }
        if (attempt < 3) {
          await sleep(5000);
          continue;
        }
        throw error;
      }
    }

    if (!sentTx) {
      throw new Error("Failed to send transaction after all attempts");
    }

    const receipt = await sentTx.wait();
    if (receipt.status === 0) {
      addLog(`Add LP transaction reverted: ${JSON.stringify(receipt)}`, "error");
      throw new Error(`Transaction reverted: ${receipt.revertReason || 'No revert reason provided'}`);
    }

    addLog("Add LP Transaction Successfully", "success");
  } catch (error) {
    addLog(`Add LP operation failed: ${error.message}`, "error");
    if (error.reason) {
      addLog(`Revert reason: ${error.reason}`, "error");
    }
    if (error.receipt) {
      addLog(`Transaction receipt: ${JSON.stringify(error.receipt)}`, "debug");
    }
    if (error.data) {
      addLog(`Revert data: ${error.data}`, "error");
    }
    throw error;
  }
}

async function runDailyActivity() {
  if (privateKeys.length === 0) {
    addLog("No valid private keys found.", "error");
    return;
  }
  addLog(`Starting daily activity for all accounts. Auto Swap: ${dailyActivityConfig.swapRepetitions}x, Auto Add LP: ${dailyActivityConfig.addLpRepetitions}x`, "info");
  activityRunning = true;
  isCycleRunning = true;
  shouldStop = false;
  hasLoggedSleepInterrupt = false;
  activeProcesses = Math.max(0, activeProcesses);
  updateMenu();
  try {
    for (let accountIndex = 0; accountIndex < privateKeys.length && !shouldStop; accountIndex++) {
      addLog(`Starting processing for account ${accountIndex + 1}`, "info");
      selectedWalletIndex = accountIndex;
      const proxyUrl = proxies[accountIndex % proxies.length] || null;
      let provider;
      addLog(`Account ${accountIndex + 1}: Using Proxy ${proxyUrl || "none"}`, "info");
      try {
        provider = await getProviderWithProxy(proxyUrl);
        await provider.getNetwork();
      } catch (error) {
        addLog(`Failed to connect to provider for account ${accountIndex + 1}: ${error.message}`, "error");
        continue;
      }
      const wallet = new ethers.Wallet(privateKeys[accountIndex], provider);
      if (!ethers.isAddress(wallet.address)) {
        addLog(`Invalid wallet address for account ${accountIndex + 1}: ${wallet.address}`, "error");
        continue;
      }
      addLog(`Processing account ${accountIndex + 1}: ${getShortAddress(wallet.address)}`, "wait");

      const swapOptions = [
        { from: USDT_ADDRESS, to: HKDA_ADDRESS, min: dailyActivityConfig.minUsdtSwap, max: dailyActivityConfig.maxUsdtSwap },
        { from: USDT_ADDRESS, to: HKDB_ADDRESS, min: dailyActivityConfig.minUsdtSwap, max: dailyActivityConfig.maxUsdtSwap },
        { from: HKDB_ADDRESS, to: USDT_ADDRESS, min: dailyActivityConfig.minHkdbSwap, max: dailyActivityConfig.maxHkdbSwap }
      ].sort(() => Math.random() - 0.5);

      for (let swapCount = 0; swapCount < dailyActivityConfig.swapRepetitions && !shouldStop; swapCount++) {
        const selectedSwap = swapOptions[swapCount % swapOptions.length];
        const amount = (Math.random() * (selectedSwap.max - selectedSwap.min) + selectedSwap.min).toFixed(3);
        try {
          const tokenContract = new ethers.Contract(selectedSwap.from, ["function balanceOf(address) view returns (uint256)"], provider);
          const balance = await tokenContract.balanceOf(wallet.address);
          const decimals = selectedSwap.from === USDT_ADDRESS ? 6 : 18;
          const formattedBalance = Number(ethers.formatUnits(balance, decimals)).toFixed(4);
          addLog(`Account ${accountIndex + 1} - Swap ${swapCount + 1} of ${dailyActivityConfig.swapRepetitions}: Balance ${tokenNames[selectedSwap.from]}: ${formattedBalance}`, "wait");
          if (balance < ethers.parseUnits(amount.toString(), decimals)) {
            addLog(`Account ${accountIndex + 1} - Swap ${swapCount + 1} of ${dailyActivityConfig.swapRepetitions}: Insufficient balance (${formattedBalance})`, "error");
            continue;
          }
          addLog(`Account ${accountIndex + 1} - Swap ${swapCount + 1} of ${dailyActivityConfig.swapRepetitions}: Swap ${amount} ${tokenNames[selectedSwap.from]} to ${tokenNames[selectedSwap.to]}`, "info");
          await swap(wallet, selectedSwap.from, selectedSwap.to, amount);
          await updateWallets();
        } catch (error) {
          addLog(`Account ${accountIndex + 1} - Swap ${swapCount + 1} of ${dailyActivityConfig.swapRepetitions}: Failed: ${error.message}`, "error");
        }
        if (swapCount < dailyActivityConfig.swapRepetitions - 1 && !shouldStop) {
          const randomDelay = Math.floor(Math.random() * (60000 - 30000 + 1)) + 30000;
          addLog(`Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before next swap...`, "delay");
          await sleep(randomDelay);
        }
      }

      if (!shouldStop) {
        const lpDelay = Math.floor(Math.random() * (15000 - 10000 + 1)) + 10000;
        addLog(`Waiting ${lpDelay / 1000} seconds before adding LP...`, "wait");
        await sleep(lpDelay);
      }

      for (let lpCount = 0; lpCount < dailyActivityConfig.addLpRepetitions && !shouldStop; lpCount++) {
        try {
          addLog(`Account ${accountIndex + 1} - Add LP ${lpCount + 1} of ${dailyActivityConfig.addLpRepetitions}`, "info");
          await addLp(wallet);
          await updateWallets();
        } catch (error) {
          addLog(`Account ${accountIndex + 1} - Add LP ${lpCount + 1} of ${dailyActivityConfig.addLpRepetitions}: Failed: ${error.message}`, "error");
        }
        if (lpCount < dailyActivityConfig.addLpRepetitions - 1 && !shouldStop) {
          const randomDelay = Math.floor(Math.random() * (60000 - 30000 + 1)) + 30000;
          addLog(`Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before next LP...`, "delay");
          await sleep(randomDelay);
        }
      }

      if (accountIndex < privateKeys.length - 1 && !shouldStop) {
        addLog(`Waiting 10 seconds before next account...`, "delay");
        await sleep(10000);
      }
    }
    if (!shouldStop && activeProcesses <= 0) {
      addLog("All accounts processed. Waiting 24 hours for next cycle.", "success");
      dailyActivityInterval = setTimeout(runDailyActivity, 24 * 60 * 60 * 1000);
    }
  } catch (error) {
    addLog(`Daily activity failed: ${error.message}`, "error");
  } finally {
    try {
      if (shouldStop) {
        const stopCheckInterval = setInterval(() => {
          if (activeProcesses <= 0) {
            clearInterval(stopCheckInterval);
            if (dailyActivityInterval) {
              clearTimeout(dailyActivityInterval);
              dailyActivityInterval = null;
              addLog("Cleared daily activity interval.", "info");
            }
            activityRunning = false;
            isCycleRunning = false;
            shouldStop = false;
            hasLoggedSleepInterrupt = false;
            activeProcesses = 0;
            addLog("Daily activity stopped successfully.", "success");
            updateMenu();
            updateStatus();
            safeRender();
          } else {
            addLog(`Waiting for ${activeProcesses} process(es) to complete...`, "info");
          }
        }, 1000);
      } else {
        activityRunning = false;
        isCycleRunning = activeProcesses > 0 || dailyActivityInterval !== null;
        updateMenu();
        updateStatus();
        safeRender();
      }
      nonceTracker = {};
    } catch (finalError) {
      addLog(`Error in runDailyActivity cleanup: ${finalError.message}`, "error");
    }
  }
}

const screen = blessed.screen({
  smartCSR: true,
  title: "EQUALHUB TESTNET AUTO BOT",
  autoPadding: true,
  fullUnicode: true,
  mouse: true,
  ignoreLocked: ["C-c", "q", "escape"]
});

const headerBox = blessed.box({
  top: 0,
  left: "center",
  width: "100%",
  height: 6,
  tags: true,
  style: { fg: "yellow", bg: "default" }
});

const statusBox = blessed.box({
  left: 0,
  top: 6,
  width: "100%",
  height: 3,
  tags: true,
  border: { type: "line", fg: "cyan" },
  style: { fg: "white", bg: "default", border: { fg: "cyan" } },
  content: "Status: Initializing...",
  padding: { left: 1, right: 1, top: 0, bottom: 0 },
  label: chalk.cyan(" Status "),
  wrap: true
});

const walletBox = blessed.list({
  label: " Wallet Information",
  top: 9,
  left: 0,
  width: "40%",
  height: "35%",
  border: { type: "line", fg: "cyan" },
  style: { border: { fg: "cyan" }, fg: "white", bg: "default", item: { fg: "white" } },
  scrollable: true,
  scrollbar: { bg: "cyan", fg: "black" },
  padding: { left: 1, right: 1, top: 0, bottom: 0 },
  tags: true,
  keys: true,
  vi: true,
  mouse: true,
  content: "Loading wallet data..."
});

const logBox = blessed.log({
  label: " Transaction Logs",
  top: 9,
  left: "41%",
  width: "60%",
  height: "100%-9",
  border: { type: "line" },
  scrollable: true,
  alwaysScroll: true,
  mouse: true,
  tags: true,
  scrollbar: { ch: "│", style: { bg: "cyan", fg: "white" }, track: { bg: "gray" } },
  scrollback: 100,
  smoothScroll: true,
  style: { border: { fg: "magenta" }, bg: "default", fg: "white" },
  padding: { left: 1, right: 1, top: 0, bottom: 0 },
  wrap: true,
  focusable: true,
  keys: true
});

const menuBox = blessed.list({
  label: " Menu ",
  top: "44%",
  left: 0,
  width: "40%",
  height: "56%",
  keys: true,
  vi: true,
  mouse: true,
  border: { type: "line" },
  style: { fg: "white", bg: "default", border: { fg: "red" }, selected: { bg: "magenta", fg: "black" }, item: { fg: "white" } },
  items: isCycleRunning
    ? ["Stop Activity", "Set Manual Config", "Clear Logs", "Refresh", "Exit"]
    : ["Start Auto Daily Activity", "Set Manual Config", "Clear Logs", "Refresh", "Exit"],
  padding: { left: 1, top: 1 }
});

const dailyActivitySubMenu = blessed.list({
  label: " Manual Config Options ",
  top: "44%",
  left: 0,
  width: "40%",
  height: "56%",
  keys: true,
  vi: true,
  mouse: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "blue" },
    selected: { bg: "blue", fg: "black" },
    item: { fg: "white" }
  },
  items: [
    "Set Swap Repetitions",
    "Set USDT Swap Range",
    "Set HKDA Swap Range",
    "Set HKDB Swap Range",
    "Set Add LP Repetitions",
    "Set LP Range (HKDA & HKDB)",
    "Back to Main Menu"
  ],
  padding: { left: 1, top: 1 },
  hidden: true
});

const configForm = blessed.form({
  label: " Enter Config Value ",
  top: "center",
  left: "center",
  width: "30%",
  height: "40%",
  keys: true,
  mouse: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "blue" }
  },
  padding: { left: 1, top: 1 },
  hidden: true
});

const minLabel = blessed.text({
  parent: configForm,
  top: 0,
  left: 1,
  content: "Min Amount:",
  style: { fg: "white" }
});

const maxLabel = blessed.text({
  parent: configForm,
  top: 4,
  left: 1,
  content: "Max Amount:",
  style: { fg: "white" }
});

const configInput = blessed.textbox({
  parent: configForm,
  top: 1,
  left: 1,
  width: "90%",
  height: 3,
  inputOnFocus: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "white" },
    focus: { border: { fg: "green" } }
  }
});

const configInputMax = blessed.textbox({
  parent: configForm,
  top: 5,
  left: 1,
  width: "90%",
  height: 3,
  inputOnFocus: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "white" },
    focus: { border: { fg: "green" } }
  }
});

const configSubmitButton = blessed.button({
  parent: configForm,
  top: 9,
  left: "center",
  width: 10,
  height: 3,
  content: "Submit",
  align: "center",
  border: { type: "line" },
  clickable: true,
  keys: true,
  style: {
    fg: "white",
    bg: "blue",
    border: { fg: "white" },
    hover: { bg: "green" },
    focus: { bg: "green", border: { fg: "yellow" } }
  }
});

screen.append(headerBox);
screen.append(statusBox);
screen.append(walletBox);
screen.append(logBox);
screen.append(menuBox);
screen.append(dailyActivitySubMenu);
screen.append(configForm);

let renderQueue = [];
let isRendering = false;
function safeRender() {
  renderQueue.push(true);
  if (isRendering) return;
  isRendering = true;
  setTimeout(() => {
    try {
      if (!isHeaderRendered) {
        figlet.text("NT EXHAUST", { font: "ANSI Shadow" }, (err, data) => {
          if (!err) headerBox.setContent(`{center}{bold}{cyan-fg}${data}{/cyan-fg}{/bold}{/center}`);
          isHeaderRendered = true;
        });
      }
      screen.render();
    } catch (error) {
      addLog(`UI render error: ${error.message}`, "error");
    }
    renderQueue.shift();
    isRendering = false;
    if (renderQueue.length > 0) safeRender();
  }, 100);
}

function adjustLayout() {
  const screenHeight = screen.height || 24;
  const screenWidth = screen.width || 80;
  headerBox.height = Math.max(6, Math.floor(screenHeight * 0.15));
  statusBox.top = headerBox.height;
  statusBox.height = Math.max(3, Math.floor(screenHeight * 0.07));
  walletBox.top = headerBox.height + statusBox.height;
  walletBox.width = Math.floor(screenWidth * 0.4);
  walletBox.height = Math.floor(screenHeight * 0.35);
  logBox.top = headerBox.height + statusBox.height;
  logBox.left = Math.floor(screenWidth * 0.41);
  logBox.width = Math.floor(screenWidth * 0.6);
  logBox.height = screenHeight - (headerBox.height + statusBox.height);
  menuBox.top = headerBox.height + statusBox.height + walletBox.height;
  menuBox.width = Math.floor(screenWidth * 0.4);
  menuBox.height = screenHeight - (headerBox.height + statusBox.height + walletBox.height);

  if (menuBox.top != null) {
    dailyActivitySubMenu.top = menuBox.top;
    dailyActivitySubMenu.width = menuBox.width;
    dailyActivitySubMenu.height = menuBox.height;
    dailyActivitySubMenu.left = menuBox.left;
    configForm.width = Math.floor(screenWidth * 0.3);
    configForm.height = Math.floor(screenHeight * 0.4);
  }

  safeRender();
}

function updateStatus() {
  try {
    const isProcessing = activityRunning || (isCycleRunning && dailyActivityInterval !== null);
    const status = activityRunning
      ? `${loadingSpinner[spinnerIndex]} ${chalk.yellowBright("Running")}`
      : isCycleRunning && dailyActivityInterval !== null
      ? `${loadingSpinner[spinnerIndex]} ${chalk.yellowBright("Waiting for next cycle")}`
      : chalk.green("Idle");
    const statusText = `Status: ${status} | Active Account: ${getShortAddress(walletInfo.address)} | Total Accounts: ${privateKeys.length} | Auto Swap: ${dailyActivityConfig.swapRepetitions}x | Auto Add LP: ${dailyActivityConfig.addLpRepetitions}x | HSK TESTNET AUTO BOT`;
    statusBox.setContent(statusText);
    if (isProcessing) {
      if (blinkCounter % 1 === 0) {
        statusBox.style.border.fg = borderBlinkColors[borderBlinkIndex];
        borderBlinkIndex = (borderBlinkIndex + 1) % borderBlinkColors.length;
      }
      blinkCounter++;
    } else {
      statusBox.style.border.fg = "cyan";
    }
    spinnerIndex = (spinnerIndex + 1) % loadingSpinner.length;
    safeRender();
  } catch (error) {
    addLog(`Status update error: ${error.message}`, "error");
  }
}

async function updateWallets() {
  try {
    const walletData = await updateWalletData();
    const header = `${chalk.bold.cyan("    Address")}      ${chalk.bold.cyan("HSK")}     ${chalk.bold.cyan("USDT")}     ${chalk.bold.cyan("HKDA")}     ${chalk.bold.cyan("HKDB")}`;
    const separator = chalk.gray("-".repeat(70));
    walletBox.setItems([header, separator, ...walletData]);
    walletBox.select(0);
    safeRender();
  } catch (error) {
    addLog(`Failed to update wallet data: ${error.message}`, "error");
  }
}

function updateLogs() {
  try {
    logBox.add(transactionLogs[transactionLogs.length - 1] || chalk.gray("No logs available."));
    safeRender();
  } catch (error) {
    addLog(`Log update failed: ${error.message}`, "error");
  }
}

function updateMenu() {
  try {
    menuBox.setItems(
      isCycleRunning
        ? ["Stop Activity", "Set Manual Config", "Clear Logs", "Refresh", "Exit"]
        : ["Start Auto Daily Activity", "Set Manual Config", "Clear Logs", "Refresh", "Exit"]
    );
    safeRender();
  } catch (error) {
    addLog(`Menu update failed: ${error.message}`, "error");
  }
}

const statusInterval = setInterval(updateStatus, 100);

logBox.key(["up"], () => {
  if (screen.focused === logBox) {
    logBox.scroll(-1);
    safeRender();
  }
});

logBox.key(["down"], () => {
  if (screen.focused === logBox) {
    logBox.scroll(1);
    safeRender();
  }
});

logBox.on("click", () => {
  screen.focusPush(logBox);
  logBox.style.border.fg = "yellow";
  menuBox.style.border.fg = "red";
  dailyActivitySubMenu.style.border.fg = "blue";
  safeRender();
});

logBox.on("blur", () => {
  logBox.style.border.fg = "magenta";
  safeRender();
});

menuBox.on("select", async (item) => {
  const action = item.getText();
  switch (action) {
    case "Start Auto Daily Activity":
      if (isCycleRunning) {
        addLog("Cycle is still running. Stop the current cycle first.", "error");
      } else {
        await runDailyActivity();
      }
      break;
    case "Stop Activity":
      shouldStop = true;
      if (dailyActivityInterval) {
        clearTimeout(dailyActivityInterval);
        dailyActivityInterval = null;
        addLog("Cleared daily activity interval.", "info");
      }
      addLog("Stopping daily activity. Please wait for ongoing process to complete.", "info");
      safeRender();
      const stopCheckInterval = setInterval(() => {
        if (activeProcesses <= 0) {
          clearInterval(stopCheckInterval);
          activityRunning = false;
          isCycleRunning = false;
          shouldStop = false;
          hasLoggedSleepInterrupt = false;
          activeProcesses = 0;
          updateMenu();
          updateStatus();
          safeRender();
        } else {
          addLog(`Waiting for ${activeProcesses} process(es) to complete...`, "info");
          safeRender();
        }
      }, 1000);
      break;
    case "Set Manual Config":
      menuBox.hide();
      dailyActivitySubMenu.show();
      setTimeout(() => {
        if (dailyActivitySubMenu.visible) {
          screen.focusPush(dailyActivitySubMenu);
          dailyActivitySubMenu.style.border.fg = "yellow";
          logBox.style.border.fg = "magenta";
          safeRender();
        }
      }, 100);
      break;
    case "Clear Logs":
      clearTransactionLogs();
      break;
    case "Refresh":
      await updateWallets();
      addLog("Data refreshed.", "success");
      break;
    case "Exit":
      clearInterval(statusInterval);
      process.exit(0);
  }
});

dailyActivitySubMenu.on("select", (item) => {
  const action = item.getText();
  switch (action) {
    case "Set Swap Repetitions":
      configForm.configType = "swapRepetitions";
      configForm.setLabel(" Enter Swap Repetitions ");
      minLabel.hide();
      maxLabel.hide();
      configInput.setValue(dailyActivityConfig.swapRepetitions.toString());
      configInputMax.setValue("");
      configInputMax.hide();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          safeRender();
        }
      }, 100);
      break;
    case "Set USDT Swap Range":
      configForm.configType = "usdtSwapRange";
      configForm.setLabel(" Enter USDT Swap Range ");
      minLabel.show();
      maxLabel.show();
      configInput.setValue(dailyActivityConfig.minUsdtSwap.toString());
      configInputMax.setValue(dailyActivityConfig.maxUsdtSwap.toString());
      configInputMax.show();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          safeRender();
        }
      }, 100);
      break;
    case "Set HKDA Swap Range":
      configForm.configType = "hkdaSwapRange";
      configForm.setLabel(" Enter HKDA Swap Range ");
      minLabel.show();
      maxLabel.show();
      configInput.setValue(dailyActivityConfig.minHkdaSwap.toString());
      configInputMax.setValue(dailyActivityConfig.maxHkdaSwap.toString());
      configInputMax.show();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          safeRender();
        }
      }, 100);
      break;
    case "Set HKDB Swap Range":
      configForm.configType = "hkdbSwapRange";
      configForm.setLabel(" Enter HKDB Swap Range ");
      minLabel.show();
      maxLabel.show();
      configInput.setValue(dailyActivityConfig.minHkdbSwap.toString());
      configInputMax.setValue(dailyActivityConfig.maxHkdbSwap.toString());
      configInputMax.show();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          safeRender();
        }
      }, 100);
      break;
    case "Set Add LP Repetitions":
      configForm.configType = "addLpRepetitions";
      configForm.setLabel(" Enter Add LP Repetitions ");
      minLabel.hide();
      maxLabel.hide();
      configInput.setValue(dailyActivityConfig.addLpRepetitions.toString());
      configInputMax.setValue("");
      configInputMax.hide();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          safeRender();
        }
      }, 100);
      break;
    case "Set LP Range (HKDA & HKDB)":
      configForm.configType = "lpRange";
      configForm.setLabel(" Enter LP Range (HKDA & HKDB) ");
      minLabel.show();
      maxLabel.show();
      configInput.setValue(dailyActivityConfig.minHkdaLp.toString());
      configInputMax.setValue(dailyActivityConfig.maxHkdaLp.toString());
      configInputMax.show();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          safeRender();
        }
      }, 100);
      break;
    case "Back to Main Menu":
      dailyActivitySubMenu.hide();
      menuBox.show();
      setTimeout(() => {
        if (menuBox.visible) {
          screen.focusPush(menuBox);
          menuBox.style.border.fg = "cyan";
          dailyActivitySubMenu.style.border.fg = "blue";
          logBox.style.border.fg = "magenta";
          safeRender();
        }
      }, 100);
      break;
  }
});

configForm.on("submit", () => {
  const inputValue = configInput.getValue().trim();
  let value, maxValue;
  try {
    value = parseFloat(inputValue);
    if (configForm.configType !== "swapRepetitions" && configForm.configType !== "addLpRepetitions") {
      maxValue = parseFloat(configInputMax.getValue().trim());
      if (isNaN(maxValue) || maxValue <= 0) {
        addLog("Invalid Max Amount value. Please enter a positive number.", "error");
        configInputMax.setValue("");
        screen.focusPush(configInputMax);
        safeRender();
        return;
      }
    }
    if (isNaN(value) || value <= 0) {
      addLog("Invalid input. Please enter a positive number.", "error");
      configInput.setValue("");
      screen.focusPush(configInput);
      safeRender();
      return;
    }
  } catch (error) {
    addLog(`Invalid format: ${error.message}`, "error");
    configInput.setValue("");
    screen.focusPush(configInput);
    safeRender();
    return;
  }

  if (configForm.configType === "swapRepetitions") {
    dailyActivityConfig.swapRepetitions = Math.floor(value);
    addLog(`Swap Repetitions set to ${dailyActivityConfig.swapRepetitions}`, "success");
  } else if (configForm.configType === "usdtSwapRange") {
    if (value > maxValue) {
      addLog("Min Amount cannot be greater than Max Amount.", "error");
      configInput.setValue("");
      configInputMax.setValue("");
      screen.focusPush(configInput);
      safeRender();
      return;
    }
    dailyActivityConfig.minUsdtSwap = value;
    dailyActivityConfig.maxUsdtSwap = maxValue;
    addLog(`USDT Swap Range set to ${dailyActivityConfig.minUsdtSwap} - ${dailyActivityConfig.maxUsdtSwap}`, "success");
  } else if (configForm.configType === "hkdaSwapRange") {
    if (value > maxValue) {
      addLog("Min Amount cannot be greater than Max Amount.", "error");
      configInput.setValue("");
      configInputMax.setValue("");
      screen.focusPush(configInput);
      safeRender();
      return;
    }
    dailyActivityConfig.minHkdaSwap = value;
    dailyActivityConfig.maxHkdaSwap = maxValue;
    addLog(`HKDA Swap Range set to ${dailyActivityConfig.minHkdaSwap} - ${dailyActivityConfig.maxHkdaSwap}`, "success");
  } else if (configForm.configType === "hkdbSwapRange") {
    if (value > maxValue) {
      addLog("Min Amount cannot be greater than Max Amount.", "error");
      configInput.setValue("");
      configInputMax.setValue("");
      screen.focusPush(configInput);
      safeRender();
      return;
    }
    dailyActivityConfig.minHkdbSwap = value;
    dailyActivityConfig.maxHkdbSwap = maxValue;
    addLog(`HKDB Swap Range set to ${dailyActivityConfig.minHkdbSwap} - ${dailyActivityConfig.maxHkdbSwap}`, "success");
  } else if (configForm.configType === "addLpRepetitions") {
    dailyActivityConfig.addLpRepetitions = Math.floor(value);
    addLog(`Add LP Repetitions set to ${dailyActivityConfig.addLpRepetitions}`, "success");
  } else if (configForm.configType === "lpRange") {
    if (value > maxValue) {
      addLog("Min Amount cannot be greater than Max Amount.", "error");
      configInput.setValue("");
      configInputMax.setValue("");
      screen.focusPush(configInput);
      safeRender();
      return;
    }
    dailyActivityConfig.minHkdaLp = value;
    dailyActivityConfig.maxHkdaLp = maxValue;
    dailyActivityConfig.minHkdbLp = value;
    dailyActivityConfig.maxHkdbLp = maxValue;
    addLog(`LP Range for HKDA & HKDB set to ${value} - ${maxValue}`, "success");
  }
  saveConfig();
  updateStatus();

  configForm.hide();
  dailyActivitySubMenu.show();
  setTimeout(() => {
    if (dailyActivitySubMenu.visible) {
      screen.focusPush(dailyActivitySubMenu);
      dailyActivitySubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

configInput.key(["enter"], () => {
  if (configForm.configType === "usdtSwapRange" || configForm.configType === "hkdaSwapRange" || configForm.configType === "hkdbSwapRange" || configForm.configType === "lpRange") {
    screen.focusPush(configInputMax);
  } else {
    configForm.submit();
    screen.focusPush(configSubmitButton);
  }
});

configInputMax.on("submit", () => {
  configForm.submit();
});

configSubmitButton.on("press", () => {
  configForm.submit();
});

configSubmitButton.on("click", () => {
  configForm.submit();
});

configForm.key(["escape"], () => {
  configForm.hide();
  dailyActivitySubMenu.show();
  setTimeout(() => {
    if (dailyActivitySubMenu.visible) {
      screen.focusPush(dailyActivitySubMenu);
      dailyActivitySubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

dailyActivitySubMenu.key(["escape"], () => {
  dailyActivitySubMenu.hide();
  menuBox.show();
  setTimeout(() => {
    if (menuBox.visible) {
      screen.focusPush(menuBox);
      menuBox.style.border.fg = "cyan";
      dailyActivitySubMenu.style.border.fg = "blue";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

screen.key(["escape", "q", "C-c"], () => {
  addLog("Exiting application", "info");
  clearInterval(statusInterval);
  process.exit(0);
});

async function initialize() {
  try {
    loadConfig();
    loadPrivateKeys();
    loadProxies();
    updateStatus();
    await updateWallets();
    updateLogs();
    safeRender();
    menuBox.focus();
  } catch (error) {
    addLog(`Initialization error: ${error.message}`, "error");
  }
}

setTimeout(() => {
  adjustLayout();
  screen.on("resize", adjustLayout);
}, 100);

initialize();
